#include <errno.h>          /* errno */
#include <libudev.h>        /* udev */
#include <stdio.h>          /* fopen() */
#include <string.h>         /* strerror() */
#include <unistd.h>         /* access() */

#include "sield-log.h"          /* log_fn() */
#include "sield-udev-helper.h"

static const char *UDEV_RULE_FILE = "/etc/udev/rules.d/999-sield.rules";

/*
 * Return a udev enumeration context to list
 * devices with given subsystem.
 */
struct udev_enumerate *enumerate_devices_with_subsystem(
        struct udev *udev, const char *subsystem)
{
    int rt = 0;
    struct udev_enumerate *enumerate = NULL;

    enumerate = udev_enumerate_new(udev);
    if (enumerate == NULL) {
        log_fn("[udev] Could not initialize enumeration context");
        return NULL;
    }

    rt = udev_enumerate_add_match_subsystem(enumerate, subsystem);
    if (rt != 0) {
        log_fn("[udev] Failed to setup enumeration filter.");
        return NULL;
    }

    rt = udev_enumerate_scan_devices(enumerate);
    if (rt != 0) {
        log_fn("[udev] Failed to scan enumeration devices.");
        return NULL;
    }

    return enumerate;
}

/*
 * Return a listening udev_monitor with given
 * event source, subsystem and device type.
 */
struct udev_monitor *monitor_device_with_subsystem_devtype(
        struct udev *udev, const char *event_source,
        const char *subsystem, const char *devtype)
{
    int rt = 0;
    struct udev_monitor *monitor = NULL;

    monitor = udev_monitor_new_from_netlink(udev, event_source);
    if (monitor == NULL) {
        log_fn("[udev] Failed to setup a new udev_monitor.");
        return NULL;
    }

    rt = udev_monitor_filter_add_match_subsystem_devtype(
            monitor, subsystem, devtype);
    if (rt != 0) {
        log_fn("[udev] Failed to setup monitor filter.");
        return NULL;
    }

    rt = udev_monitor_enable_receiving(monitor);
    if (rt != 0) {
        log_fn("[udev] Failed to bind udev_monitor to event source.");
        return NULL;
    }

    return monitor;
}

/* Return a udev_device with given action, else return NULL */
struct udev_device *receive_device_with_action(
        struct udev_monitor *monitor, const char *action)
{
    struct udev_device *device = udev_monitor_receive_device(monitor);

    if (device != NULL) {
        const char *actual_action = udev_device_get_action(device);
        if (strcmp(actual_action, action) == 0) return device;
    }

    return NULL;
}

/* Delete udev rule file. */
int delete_udev_rule(void)
{
    /* File doesn't exist */
    if (access(UDEV_RULE_FILE, F_OK) == -1) return 0;

    if (remove(UDEV_RULE_FILE) == -1) {
        log_fn("remove: %s: %s", UDEV_RULE_FILE, strerror(errno));
        return -1;
    }

    return 0;
}

/* Write the udev rule to prevent automount. */
int write_udev_rule(void)
{
    const char *rule =
        "ACTION==\"add|change\", SUBSYSTEM==\"block\","
        "SUBSYSTEMS==\"usb\", ENV{UDISKS_PRESENTATION_HIDE}=\"1\","
        "ENV{UDISKS_PRESENTATION_NOPOLICY}=\"1\","
        "ENV{UDISKS_AUTOMOUNT_HINT}=\"never\","
        "ENV{UDISKS_IGNORE}=\"1\", ENV{UDISKS_AUTO}=\"0\"";
    FILE *fp = NULL;

    /* Rule file already exists */
    if (access(UDEV_RULE_FILE, F_OK) == 0) return 0;

    fp = fopen(UDEV_RULE_FILE, "w");
    if (fp == NULL) {
        log_fn("fopen: %s: %s", UDEV_RULE_FILE, strerror(errno));
        return -1;
    }

    fprintf(fp, "%s\n", rule);

    fclose(fp);
    return 0;
}
