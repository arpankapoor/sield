#include <errno.h>              /* errno */
#include <libudev.h>            /* udev */
#include <stdlib.h>             /* exit() */
#include <string.h>             /* strcmp() */
#include <sys/mount.h>          /* umount() */
#include <unistd.h>             /* getpid() */
#include "sield-config.h"       /* get_sield_attr_int() */
#include "sield-daemon.h"       /* become_daemon() */

#include <libudev.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "sield-av.h"
#include "sield-config.h"
#include "sield-daemon.h"
#include "sield-log.h"
#include "sield-mount.h"
#include "sield-passwd-ask.h"
#include "sield-share.h"
#include "sield-udev-helper.h"

static void handle_device(struct udev_device *device,
                          struct udev_device *parent)
{
    /* Log device information. */
    log_block_device_info(device, parent);

    /***********************
     * Basic device info.
    ***********************/
    const char *devnode = udev_device_get_devnode(device);
    const char *manufacturer = udev_device_get_sysattr_value(parent, "manufacturer");
    const char *product = udev_device_get_sysattr_value(parent, "product");
    /**********************/

    /* Incorrect password is given. */
    if (ask_passwd(manufacturer, product, devnode) != 1) return;

    long int scan = get_sield_attr_int("scan");
    if (scan != 0) scan = 1;

    if (scan == 1) {

        /* Mount as read-only for virus scan */
        /* TODO: Mount at a temporary directory */
        char *rd_only_mtpt = mount_device(device, 1);
        if (rd_only_mtpt)
            log_fn("Mounted %s (%s %s) at %s as read-only for virus scan.",
                   devnode, manufacturer, product, rd_only_mtpt);
        else return;

        /* Scan the device for viruses. */
        int av_result = is_infected(rd_only_mtpt);

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
        if (av_result != 0) return;
    }

    /* Check if mount should be read-only */
    long int ro = get_sield_attr_int("read only");
    if (ro != 0) ro = 1;

    /* Mount the device */
    char *mount_pt = mount_device(device, ro);

    if (mount_pt) {
        log_fn("Mounted %s (%s %s) at %s as %s.",
               devnode, manufacturer, product, mount_pt,
               ro == 1 ? "read-only" : "read-write");

        if (get_sield_attr_int("share") == 1
            && samba_share(mount_pt, manufacturer, product) != -1)
            log_fn("Shared %s on the samba network.", mount_pt);

        if (has_unmounted(mount_pt)) {
            log_fn("%s was unmounted.", devnode);
            if (restore_smb_conf()) log_fn("Restored smb.conf");
        }

        free(mount_pt);
    }
}

int main(int argc, char *argv[])
{
    struct udev *udev = NULL;
    struct udev_monitor *monitor = NULL;
    struct udev_enumerate *enumerate = NULL;
    struct udev_list_entry *devices_list = NULL;
    struct udev_list_entry *dev_list_entry = NULL;
    struct udev_device *device = NULL;
    struct udev_device *parent = NULL;

    /* TODO: Delete pid file on exit */
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

    /* Device monitor setup successfully. */
    log_fn("Device monitor setup successfully.");

    /* List and handle all devices that are already plugged in. */
    enumerate = enumerate_devices_with_subsystem(udev, "block");
    devices_list = udev_enumerate_get_list_entry(enumerate);

    udev_list_entry_foreach(dev_list_entry, devices_list) {
        char *mountpoint = NULL;
        const char *devnode = NULL;

        device = udev_device_new_from_syspath(
                    udev, udev_list_entry_get_name(dev_list_entry));

        /* Handle device only if it has a mountable partition. */
        if (strcmp(udev_device_get_devtype(device), "partition") != 0) {
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
