#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libudev.h>
/*#include <locale.h>
#include <unistd.h>
#include <sys/mount.h> */
#include "sield-log.h"

/*********************** UDEV EXTENSIONS ****************************/

/* Return a listening udev_monitor with given
 * event source, subsystem and device type. */
struct udev_monitor *monitor_device_with_subsystem_devtype(
	struct udev *udev, const char *event_source,
	const char *subsystem, const char *devtype)
{
	struct udev_monitor *monitor = udev_monitor_new_from_netlink(
					udev, event_source);
	if (!monitor) {
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
		if (strcmp(actual_action, action) == 0) return device;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	struct udev *udev = udev_new();
	udev_set_log_fn(udev, udev_custom_log_fn);

	/* Monitor block devices */
	struct udev_monitor *monitor = monitor_device_with_subsystem_devtype(
					udev, "udev", "block", NULL);
	if (!monitor) exit(EXIT_FAILURE);

	while (1) {
		/* Receive udev_device for any "block" device which was
		 * plugged in ("add"ed) to the system. */
		struct udev_device *device = receive_device_with_action(
						monitor, "add");

		/* The device should be using USB */
		struct udev_device *parent = udev_device_get_parent_with_subsystem_devtype(
						device, "usb", "usb_device");

		if (device && parent) {
			log_block_device_info(device, parent);

			/* Parent will also be cleaned up */
			udev_device_unref(device);
		}
	}

	udev_monitor_unref(monitor);
	udev_unref(udev);
	return 0;
}
