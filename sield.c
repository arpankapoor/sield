#include <libudev.h>
#include <syslog.h>	/* Log priority */
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

int main (void)
{
	int rc;
	struct udev *udev;
	struct udev_monitor *monitor;
	struct udev_device *device, *parent;

       	udev = udev_new();
	udev_set_log_fn(udev, udev_custom_log_fn);
	if (!udev) {
		fprintf(stderr, "error: udev_new() returned NULL");
		exit(EXIT_FAILURE);
	}

	/* Log every possible message */
	/* udev_set_log_priority(udev, LOG_DEBUG); */

	/* Setup a udev_monitor to monitor block devices with any device type */
	monitor = udev_monitor_new_from_netlink(udev, "udev");
	rc = udev_monitor_filter_add_match_subsystem_devtype(monitor, "block", NULL);
	if (rc < 0) {
		fprintf(stderr, "error: udev_monitor_filter_add_match_subsystem_devtype()");
		exit(EXIT_FAILURE);
	}

	rc = udev_monitor_enable_receiving(monitor);
	if (rc < 0) {
		fprintf(stderr, "error: udev_monitor_enable_receiving");
		exit(EXIT_FAILURE);
	}

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
