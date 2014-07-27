#include <errno.h>              /* errno */
#include <fcntl.h>              /* fcntl() */
#include <libudev.h>            /* udev */
#include <signal.h>             /* sigaction() */
#include <stdlib.h>             /* free(), exit() */
#include <string.h>             /* strcmp() */
#include <sys/mount.h>          /* umount() */
#include <sys/wait.h>           /* waitpid() */
#include <unistd.h>             /* getpid() */

#include "sield-av.h"           /* is_infected() */
#include "sield-config.h"       /* get_sield_attr_int() */
#include "sield-daemon.h"       /* become_daemon() */
#include "sield-log.h"          /* log_fn() */
#include "sield-mount.h"        /* mount_device() */
#include "sield-passwd-ask.h"   /* ask_passwd() */
#include "sield-pid.h"          /* rm_pidfile() */
#include "sield-share.h"        /* samba_share() */
#include "sield-udev-helper.h"  /* monitor_device_with_subsystem_devtype() */

static void handler(int signum);
static void _handle_device(struct udev_device *device,
                           struct udev_device *parent);
static void handle_device(struct udev_device *device,
                          struct udev_device *parent);
static int handle_plugged_in_devices(
        struct udev *udev, const char *subsystem, const char *devtype);

/* Catch signals */
static void handler(int signum)
{
    if (signum == SIGCHLD) {
        int status;

        while (waitpid(-1, &status, WNOHANG) > 0) continue;
        return;
    }

    if (signum == SIGSEGV || signum == SIGTERM) {
        if (signum == SIGSEGV) log_fn("Segmentation fault.");
        if (signum == SIGTERM) log_fn("SIGTERM received.");

        /* cleanup */
        delete_udev_rule();
        rm_pidfile();
        restore_smb_conf();
        exit(signum);
    }
}

/* Create a new process to handle a detected device */
static void handle_device(struct udev_device *device,
                          struct udev_device *parent)
{
    switch (fork()) {
        case -1:
            log_fn("Could not create a new process to handle device %s",
                   udev_device_get_devnode(device));
            return;
        case 0: break;
        default: return;
    }

    /* Child process executes this. */
    _handle_device(device, parent);
    exit(EXIT_SUCCESS);
}

/* Sequential steps to execute for handling a device */
static void _handle_device(struct udev_device *device,
                           struct udev_device *parent)
{
    /*********************/
    /* Basic device info */
    /*********************/
    const char *devnode = udev_device_get_devnode(device);
    const char *manufacturer = udev_device_get_sysattr_value(parent, "manufacturer");
    const char *product = udev_device_get_sysattr_value(parent, "product");
    /**********************/

    int scan = get_sield_attr_bool("scan");
    int readonly = get_sield_attr_bool("read only");
    char *mount_pt = NULL;

    /* Log device information. */
    log_block_device_info(device, parent);

    /* Incorrect password is given. */
    if (ask_passwd(manufacturer, product, devnode) != 1) return;

    /* Don't scan iff scan == 0 */
    if (scan != 0) {
        char *rd_only_mtpt = NULL;
        int av_result;

        /* Mount as read-only for virus scan */
        /* TODO: Mount at a temporary directory */
        rd_only_mtpt = mount_device(device, 1);
        if (rd_only_mtpt)
            log_fn("Mounted %s (%s %s) at %s as read-only for virus scan.",
                   devnode, manufacturer, product, rd_only_mtpt);
        else return;

        /* Scan the device for viruses. */
        av_result = is_infected(rd_only_mtpt);

        /* Unmount*/
        if (umount(rd_only_mtpt) == -1) {
            free(rd_only_mtpt);
            return;
        } else {
            log_fn("Unmounted %s", rd_only_mtpt);
            free(rd_only_mtpt);
        }

        /*
         * Either
         * 1. Virus(es) found.
         *  OR
         * 2. Error(s) occurred.
         */
        if (av_result == 1) return;

        /* If errors occurred, mount as read only. */
        if (av_result == 2) readonly = 1;
    }

    /* Mount the device */
    mount_pt = mount_device(device, readonly);

    if (mount_pt) {
        log_fn("Mounted %s (%s %s) at %s as %s.",
               devnode, manufacturer, product, mount_pt,
               readonly == 1 ? "read-only" : "read-write");

        if (get_sield_attr_bool("share") == 1
            && samba_share(mount_pt, manufacturer, product) != -1) {

            log_fn("Shared %s on the samba network.", mount_pt);

            if (has_unmounted(mount_pt)) {
                log_fn("%s was unmounted.", devnode);
                if (restore_smb_conf()) log_fn("Restored smb.conf");
            }
        }

        free(mount_pt);
    }
}

static int handle_plugged_in_devices(
        struct udev *udev, const char *subsystem, const char *devtype)
{
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices_list = NULL;
    struct udev_list_entry *dev_list_entry = NULL;

    /* List and handle all devices that are already plugged in. */
    enumerate = enumerate_devices_with_subsystem(udev, subsystem);
    if (enumerate == NULL) return -1;

    devices_list = udev_enumerate_get_list_entry(enumerate);

    udev_list_entry_foreach(dev_list_entry, devices_list) {
        char *mountpoint = NULL;
        const char *devnode = NULL;
        struct udev_device *device = NULL;
        struct udev_device *parent = NULL;

        device = udev_device_new_from_syspath(
                    udev, udev_list_entry_get_name(dev_list_entry));

        /* Handle device only if it has a mountable partition. */
        if (strcmp(udev_device_get_devtype(device), devtype) != 0) {
            udev_device_unref(device);
            continue;
        }

        /* Ensure it a USB device. */
        parent = udev_device_get_parent_with_subsystem_devtype(
                    device, "usb", "usb_device");

        if (parent == NULL) {
            udev_device_unref(device);
            continue;
        }

        devnode = udev_device_get_devnode(device);
        mountpoint = get_mountpoint(devnode);

        /* Device is already mounted */
        if (mountpoint != NULL) {
            /* Check if "remount" configuration is set */
            if (get_sield_attr_int("remount") == 1) {
                /* Unmount device */
                if (umount(mountpoint) == -1) {
                    log_fn("umount(): %s: %s", mountpoint, strerror(errno));
                    udev_device_unref(device);
                    free(mountpoint);
                    continue;
                } else {
                    log_fn("Unmounted %s (%s)", mountpoint, devnode);
                }
            } else {
                log_fn("Ignoring %s mounted at %s", devnode, mountpoint);
            }

            free(mountpoint);
        }

        handle_device(device, parent);

        udev_device_unref(device);
    }

    udev_enumerate_unref(enumerate);

    return 0;
}

int main(int argc, char *argv[])
{
    size_t i;
    int fd, saved_flags;
    const int signals[] = {SIGTERM, SIGCHLD, SIGSEGV};
    struct sigaction action;
    struct udev *udev = NULL;
    struct udev_monitor *monitor = NULL;
    struct udev_device *device = NULL;
    struct udev_device *parent = NULL;

    /* Setup signal handlers */
    action.sa_handler = handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    /* Assign handler to any signals we care about */
    for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
        int signal = signals[i];
        sigaction(signal, &action, NULL);
    }

    if (become_daemon() == -1) {
        log_fn("SysV daemon creation failed. Quitting.");
        exit(EXIT_FAILURE);
    }

    /* Daemon creation successful */
    log_fn("Started daemon with PID %ld.", (long int)getpid());

    udev = udev_new();
    if (udev == NULL) {
        log_fn("udev object not created. Quitting.");
        exit(EXIT_FAILURE);
    }

    /* Custom logging function */
    udev_set_log_fn(udev, udev_custom_log_fn);

    /* Monitor block devices with a partition */
    monitor = monitor_device_with_subsystem_devtype(
                udev, "udev", "block", "partition");
    if (monitor == NULL) {
        log_fn("Failed to initialize udev monitor. Quitting.");
        udev_unref(udev);
        exit(EXIT_FAILURE);
    }

    fd = udev_monitor_get_fd(monitor);

    /* Make the monitor BLOCKING */
    saved_flags = fcntl(fd, F_GETFL);
    /* Mask out O_NONBLOCK */
    fcntl(fd, F_SETFL, saved_flags & ~O_NONBLOCK);

    /* Device monitor setup successfully. */
    log_fn("Device monitor setup successfully.");

    handle_plugged_in_devices(udev, "block", "partition");

    while (1) {
        /* Check if enabled. */
        if (get_sield_attr_int("enable") != 1) {
            sleep(1);
            delete_udev_rule();
            continue;
        }

        write_udev_rule();

        /*
         * Receive udev_device for any "block" device which was
         * plugged in ("add"ed) to the system.
         */
        device = receive_device_with_action(monitor, "add");
        if (device == NULL) {
            sleep(1);
            continue;
        }

        /* The device should be using USB */
        parent = udev_device_get_parent_with_subsystem_devtype(
                    device, "usb", "usb_device");
        if (parent == NULL) {
            udev_device_unref(device);
            sleep(1);
            continue;
        }

        /* Take care of the device. */
        handle_device(device, parent);

        /* Parent will also be cleaned up */
        udev_device_unref(device);
    }

    udev_monitor_unref(monitor);
    udev_unref(udev);
    return 0;
}
