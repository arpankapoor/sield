#include <libudev.h>
#include <string.h>

#include "sield-log.h"

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
