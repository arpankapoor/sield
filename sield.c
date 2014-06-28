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
#include "sield-passwd-dialog.h"
#include "sield-share.h"
#include "sield-udev-helper.h"

static void handle_device(struct udev_device *device,
		struct udev_device *parent)
{
	/* Log device information. */
	log_block_device_info(device, parent);

	/***********************
	    Basic device info.
	 ***********************/
	const char *devnode =
		udev_device_get_devnode(device);

	const char *manufacturer =
		udev_device_get_sysattr_value(parent, "manufacturer");

	const char *product =
		udev_device_get_sysattr_value(parent, "product");

	/**********************/

	/* Incorrect password is given. */
	if (! ask_passwd_dialog(manufacturer, product)) return;

	/* Mount as read-only for virus scan */
	/* TODO: Mount at a temporary directory */
	char *rd_only_mtpt = mount_device(device, 1);
	if (rd_only_mtpt)
		log_fn("Mounted %s (%s %s) at %s as read-only for virus scan.",
			devnode, manufacturer, product, rd_only_mtpt);
	else return;

	/* Scan the device for viruses. */
	int av_result = virus_scan(rd_only_mtpt);

	/* Unmount*/
	if (unmount(rd_only_mtpt) == -1) {
		free(rd_only_mtpt);
		return;
	} else {
		log_fn("Unmounted %s", rd_only_mtpt);
		free(rd_only_mtpt);
	}

	/*
	 * Either
	 * 1. Virus(es) found.
	 * 	OR
	 * 2. Error(s) occurred.
	 */
	if (av_result != 0) return;

	/* Check if mount should be read-only */
	long int ro = get_sield_attr_int("read only");
	if (ro == -1) ro = 1;

	/* Mount the device */
	char *mount_pt = mount_device(device, ro);

	if (mount_pt) {
		log_fn("Mounted %s (%s %s) at %s as %s.",
			devnode, manufacturer, product, mount_pt,
			ro == 1 ? "read-only" : "read-write");

		if (samba_share(mount_pt))
			log_fn("Shared %s on the samba network.", mount_pt);

		free(mount_pt);
	}
}

int main(int argc, char **argv)
{
	if (become_daemon() == -1) {
		log_fn("Daemon creation failed. Quitting.");
		exit(EXIT_FAILURE);
	}

	struct udev *udev = udev_new();
	udev_set_log_fn(udev, udev_custom_log_fn);

	/* Monitor block devices */
	struct udev_monitor *monitor = monitor_device_with_subsystem_devtype(
					udev, "udev", "block", "partition");
	if (! monitor) {
		log_fn("Failed to initialize udev monitor. Quitting.");
		exit(EXIT_FAILURE);
	}

	/* List and handle all devices that are already plugged in. */
	struct udev_enumerate *enumerate = udev_enumerate_new(udev);
	udev_enumerate_add_match_subsystem(enumerate, "block");
	udev_enumerate_scan_devices(enumerate);
	struct udev_list_entry *devices = udev_enumerate_get_list_entry(enumerate);
	struct udev_list_entry *dev_list_entry;

	udev_list_entry_foreach(dev_list_entry, devices) {
		const char *path = udev_list_entry_get_name(dev_list_entry);
		struct udev_device *dev = udev_device_new_from_syspath(udev, path);

		const char *devtype = udev_device_get_devtype(dev);

		/* Ignore devices other than partitions. */
		if (strcmp(devtype, "partition")) continue;

		/* Ensure it is a usb device. */
		struct udev_device *parent = udev_device_get_parent_with_subsystem_devtype(
				dev, "usb", "usb_device");
		if (! parent) continue;

		handle_device(dev, parent);

		udev_device_unref(dev);
	}

	while (1) {
		/* Check if enabled. */
		if (get_sield_attr_int("enable") == 0) {
			sleep(1);
			continue;
		}

		/*
		 * Receive udev_device for any "block" device which was
		 * plugged in ("add"ed) to the system.
		 */
		struct udev_device *device = receive_device_with_action(
						monitor, "add");
		if (! device) {
			sleep(1);
			continue;
		}

		/* The device should be using USB */
		struct udev_device *parent = udev_device_get_parent_with_subsystem_devtype(
						device, "usb", "usb_device");
		if (! parent) {
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
