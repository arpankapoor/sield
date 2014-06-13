#ifndef _SIELD_UDEV_HELPER_H_
#define _SIELD_UDEV_HELPER_H_

#include <libudev.h>

/*
 * udev helper functions
 */

struct udev_monitor *monitor_device_with_subsystem_devtype(
	struct udev *udev, const char *event_source,
	const char *subsystem, const char *devtype);

struct udev_device *receive_device_with_action(
	struct udev_monitor *monitor, const char *action);

#endif