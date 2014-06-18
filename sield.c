#include <libudev.h>
#include <stdio.h>
#include <stdlib.h>

#include "sield-config.h"
#include "sield-log.h"
#include "sield-mount.h"
#include "sield-passwd-dialog.h"
#include "sield-udev-helper.h"

int main(int argc, char **argv)
{
	struct udev *udev = udev_new();
	udev_set_log_fn(udev, udev_custom_log_fn);

	/* Monitor block devices */
	struct udev_monitor *monitor = monitor_device_with_subsystem_devtype(
					udev, "udev", "block", "partition");
	if (! monitor) {
		log_fn("Failed to initialize udev monitor. Quitting.");
		exit(EXIT_FAILURE);
	}

	while (1) {
		/* Check if enabled. */
		if (get_sield_attr_int("enable") == 0) continue;

		/*
		 * Receive udev_device for any "block" device which was
		 * plugged in ("add"ed) to the system.
		 */
		struct udev_device *device = receive_device_with_action(
						monitor, "add");
		if (! device) continue;

		/* The device should be using USB */
		struct udev_device *parent = udev_device_get_parent_with_subsystem_devtype(
						device, "usb", "usb_device");
		if (! parent) {
			udev_device_unref(device);
			continue;
		}

		/* Log device information. */
		log_block_device_info(device, parent);

		/* Basic device info. */
		const char *manufacturer =
			udev_device_get_sysattr_value(parent, "manufacturer");

		const char *product =
			udev_device_get_sysattr_value(parent, "product");
		/**********************/

		/* If correct password is given. */
		if (ask_passwd_dialog(manufacturer, product)) {

			/* Check if mount should be read-only */
			long int ro = get_sield_attr_int("readonly");
			if (ro == -1) ro = 1;

			/* Mount the device */
			char *mount_pt = mount_device(device, ro);

			if (mount_pt) {
				log_fn("Mounted %s %s at %s as %s.",
					manufacturer, product, mount_pt,
					ro == 1 ? "read-only" : "read-write");

				/* TODO: Scan the device. */
				char *avpath = get_sield_attr("avpath");
				if (! avpath) avpath = strdup("clamscan");

				char *avopts = get_sield_attr("avopts");

				int has_virus = system(avpath);

				/* Clam AV returns 1 on detecting viruses. */
			}
		}

		/* Parent will also be cleaned up */
		udev_device_unref(device);
	}

	udev_monitor_unref(monitor);
	udev_unref(udev);
	return 0;
}
