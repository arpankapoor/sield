#ifndef _SIELD_H_
#define _SIELD_H_

#include <stdarg.h>
#include <libudev.h>

/*
 * Logging functions
 */
#define log_fn(format, ...) _log_fn(format"\n", ##__VA_ARGS__)
void _log_fn(const char *format, ...);
void log_block_device_info(struct udev_device *device,
	struct udev_device *parent);


/*
 * udev helper functions
 */
void udev_custom_log_fn(struct udev *udev,
	int priority, const char *file, int line, const char *fn,
	const char *format, va_list args);

struct udev_monitor *monitor_device_with_subsystem_devtype(
	struct udev *udev, const char *event_source,
	const char *subsystem, const char *devtype);

struct udev_device *receive_device_with_action(
	struct udev_monitor *monitor, const char *action);

#endif
