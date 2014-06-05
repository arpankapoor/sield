#include <libudev.h>
/*#include <syslog.h>*/	/* Log priority */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/*#include <locale.h>
#include <unistd.h>
#include <sys/mount.h> */

const char *LOG_FILE = "/var/log/sield.log";

/*********************** UDEV EXTENSIONS ************************/

void udev_custom_log_fn(struct udev *udev,
	int priority, const char *file, int line, const char *fn,
	const char *format, va_list args)
{
	FILE *LOG_FP = fopen(LOG_FILE, "a");
	if (!LOG_FP) return;

	fprintf(LOG_FP, "libudev: %s: ", fn);
	vfprintf(LOG_FP, format, args);

	fclose(LOG_FP);
}

/****************************************************************/

/* Write message along with a newline to the LOG_FILE */
void log_fn(const char *msg)
{
	FILE *LOG_FP = fopen(LOG_FILE, "a");
	if(!LOG_FP) return;

	fprintf(LOG_FP, "%s\n", msg);
	fclose(LOG_FP);
}

/* Return a listening udev_monitor with given
 * event source, subsystem and device type. */
struct udev_monitor *monitor_device_with_subsytem_devtype(
	struct udev *udev, const char *event_source,
	const char *subsystem, const char *devtype)
{
	struct udev_monitor *monitor;
	monitor = udev_monitor_new_from_netlink(udev, event_source);
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

int main (void)
{
	struct udev *udev;
	struct udev_monitor *monitor;
	struct udev_device *device, *parent;

       	udev = udev_new();
	udev_set_log_fn(udev, udev_custom_log_fn);

	/* Uncomment to increase log priority */
	/** udev_set_log_priority(udev, LOG_DEBUG); **/

	/* Monitor block devices */
	monitor = monitor_device_with_subsytem_devtype(
			udev, "udev", "block", NULL);
	if (!monitor) exit(EXIT_FAILURE);

	while (1) {
		/* udev_monitor_receive_device is NONBLOCKING. */
		device = udev_monitor_receive_device(monitor);
		if (device) {
			/* Ensure that the device is a USB "disk". */
			const char *action = udev_device_get_action(device);
			const char *devtype = udev_device_get_devtype(device);
			parent = udev_device_get_parent_with_subsystem_devtype(
					device, "usb", "usb_device");

			if (parent && strcmp(action, "add") == 0) {
				printf("%s %s inserted ",
					udev_device_get_sysattr_value(parent, "manufacturer"),
					udev_device_get_sysattr_value(parent, "product"));

				if (strcmp(devtype, "disk") == 0) {
					printf ("with device node %s.\n",
						udev_device_get_devnode(device));
				} else if (strcmp(devtype, "partition") == 0) {
					printf ("with partition %s.\n",
						udev_device_get_devnode(device));
				}

				udev_device_unref(device);
			}
		}
	}

	udev_monitor_unref(monitor);
	udev_unref(udev);
	return 0;
}
