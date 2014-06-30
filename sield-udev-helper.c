#include <errno.h>
#include <libudev.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>	/* access() */

#include "sield-log.h"
#include "sield-udev-helper.h"

static const char *UDEV_RULE_FILE = "/etc/udev/rules.d/999-sield-prevent-automount.rules";

/*
 * Return a listening udev_monitor with given
 * event source, subsystem and device type.
 */
struct udev_monitor *monitor_device_with_subsystem_devtype(
	struct udev *udev, const char *event_source,
	const char *subsystem, const char *devtype)
{
	struct udev_monitor *monitor = udev_monitor_new_from_netlink(
					udev, event_source);
	if (! monitor) {
		log_fn("Failed to setup a new udev_monitor.");
		return NULL;
	}

	int rt;
	rt = udev_monitor_filter_add_match_subsystem_devtype(
		monitor, subsystem, devtype);
	if (rt != 0) {
		log_fn("Failed to setup monitor filter.");
		return NULL;
	}

	rt = udev_monitor_enable_receiving(monitor);
	if (rt != 0) {
		log_fn("Failed to bind udev_monitor to event source.");
		return NULL;
	}

	return monitor;
}

/* Return a udev_device with given action, else return NULL */
struct udev_device *receive_device_with_action(
	struct udev_monitor *monitor, const char *action)
{
	/* udev_monitor_receive_device is NONBLOCKING */
	struct udev_device *device = udev_monitor_receive_device(monitor);
	if (device) {
		const char *actual_action = udev_device_get_action(device);
		if (! strcmp(actual_action, action)) return device;
	}

	return NULL;
}

static int udev_rule_file_exists(void)
{
	return access(UDEV_RULE_FILE, F_OK) == 0;
}

/*
 * Delete udev rule file.
 *
 * Return 1 on success, 0 on error.
 */
int delete_udev_rule(void)
{
	if (! udev_rule_file_exists()) return 1;

	if (remove(UDEV_RULE_FILE) == -1) {
		log_fn("Unable to delete udev rule file: %s", strerror(errno));
		return 0;
	}

	return 1;
}

/*
 * Write the udev rule for sield.
 *
 * Return 1 on success, else return 0.
 */
int write_udev_rule(void)
{
	/* Rule file already exists */
	if (udev_rule_file_exists()) return 1;

	FILE *udev_fp = fopen(UDEV_RULE_FILE, "w");
	if (! udev_fp) {
		log_fn("Can't open udev rule file for writing: %s", strerror(errno));
		return 0;
	}

	const char *rule =
		"ACTION==\"add|change\", SUBSYSTEM==\"block\","
		"SUBSYSTEMS==\"usb\", ENV{UDISKS_PRESENTATION_HIDE}=\"1\","
		"ENV{UDISKS_PRESENTATION_NOPOLICY}=\"1\","
		"ENV{UDISKS_AUTOMOUNT_HINT}=\"never\","
		"ENV{UDISKS_IGNORE}=\"1\", ENV{UDISKS_AUTO}=\"0\"";

	fprintf(udev_fp, "%s\n", rule);

	fclose(udev_fp);
	return 1;
}
