#define _GNU_SOURCE		/* asprintf() */
#include <errno.h>		/* errno */
#include <libudev.h>
#include <stdio.h>		/* asprintf() */
#include <stdlib.h>		/* free() */
#include <string.h>		/* strdup() */
#include <sys/mount.h>		/* mount() */
#include <sys/stat.h>		/* mkdir() */

#include "sield-config.h"
#include "sield-log.h"
#include "sield-mount.h"

static char *get_mount_point(struct udev_device *device);
char *mount_device(struct udev_device *device, int ro);

static char *get_mount_point(struct udev_device *device)
{
	/* If mount point is given in the config file. */
	char *target = get_sield_attr("mountpoint");

	if (! target) {
		/* Check if device label is defined. */
		const char *fs_label = udev_device_get_property_value(
				device, "ID_FS_LABEL");

		/* Filesystem label not defined. */
		if (! fs_label) {
			target = strdup("/mnt/sield_usb");
			log_fn("Cannot find device filesystem label."
				"Using default mount point /mnt/sield_usb.");
		} else if (asprintf(&target, "/mnt/%s", fs_label) == -1) {
			target = strdup("/mnt/sield_usb");
		}
	}

	return target;
}

/*
 * Mount the given udev_device at configured mount point.
 *
 * Return the mount point on success,
 * else return NULL.
 */
char *mount_device(struct udev_device *device, int ro)
{
	/* Device node */
	const char *devnode = udev_device_get_devnode(device);

	/* Get the filesystem type */
	const char *fs_type = udev_device_get_property_value(device, "ID_FS_TYPE");

	/* Mount point */
	char *target = get_mount_point(device);

	/*
	 * Create the mountpoint if it does not already exist.
	 *
	 * Readable and writable by the owner.
	 */
	if (mkdir(target, S_IRUSR | S_IWUSR) == -1 && errno != EEXIST) {
		log_fn("Cannot create the directory: \"%s\". %s",
			target, strerror(errno));
		free(target);
		return NULL;
	}

	/* Default is read-only. */
	unsigned long mountflags = MS_RDONLY;

	if (ro == 0) mountflags = 0;

	/* MOUNT */
	if (mount(devnode, target, fs_type, mountflags, NULL) == -1) {
		log_fn("Unable to mount %s: %s", devnode, strerror(errno));
		free(target);
		return NULL;
	}

	return target;
}
