#define _GNU_SOURCE		/* asprintf() */
#include <errno.h>		/* errno */
#include <libudev.h>
#include <poll.h>
#include <stdio.h>		/* asprintf() */
#include <stdlib.h>		/* free() */
#include <string.h>		/* strdup() */
#include <sys/mount.h>		/* mount() */
#include <sys/stat.h>		/* mkdir() */

#include "sield-config.h"
#include "sield-log.h"
#include "sield-mount.h"

static const char *PROC_MOUNTS = "/proc/mounts";

static char *get_mount_point_attr(struct udev_device *device);
char *mount_device(struct udev_device *device, int ro);
int unmount(const char *target);
int is_mounted(const char *devpath);
char *get_mount_point(const char *devpath);
int has_unmounted(const char *devpath);

static char *get_mount_point_attr(struct udev_device *device)
{
	/* If mount point is given in the config file. */
	char *target = get_sield_attr("mount point");

	if (! target) {
		/* Check if device label is defined. */
		const char *fs_label = udev_device_get_property_value(
				device, "ID_FS_LABEL");

		/* Filesystem label not defined. */
		if (! fs_label) {
			target = strdup("/mnt/sield_usb");
			log_fn("Cannot find device filesystem label."
				"Using default mount point \"/mnt/sield_usb\".");
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
	char *target = get_mount_point_attr(device);

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

/* Wrapper for umount. */
int unmount(const char *target)
{
	if (umount(target) == -1) {
		log_fn("Unable to unmount %s: %s", target, strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Check if given device is present in the
 * PROC_MOUNTS file.
 *
 * Return 1 if present, else return 0.
 */
int is_mounted(const char *devpath)
{
	FILE *mount_fp = fopen(PROC_MOUNTS, "r");
	if (! mount_fp) {
		log_fn("Cannot open \"%s\" for reading.", PROC_MOUNTS);
		return 0;
	}

	char *line = NULL;
	size_t len = 0;
	int ret = 1;

	while (getline(&line, &len, mount_fp) != -1) {
		char *device = NULL;

		/* %m modifier for dynamic string allocation. */
		sscanf(line, "%ms", &device);
		ret = strcmp(device, devpath);
		if (device) free(device);

		if (ret == 0) break;
	}

	if (line) free(line);
	fclose(mount_fp);

	return ret == 0;
}

/*
 * Return given device's mount point from the
 * PROC_MOUNTS file.
 */
char *get_mount_point(const char *devpath)
{
	FILE *mount_fp = fopen(PROC_MOUNTS, "r");
	if (! mount_fp) {
		log_fn("Cannot open \"%s\" for reading.", PROC_MOUNTS);
		return 0;
	}

	char *mt_pt_copy = NULL;
	char *line = NULL;
	size_t len = 0;
	int found = 0;

	while (getline(&line, &len, mount_fp) != -1) {
		char *device = NULL, *mt_pt = NULL;

		/* %m modifier for dynamic string allocation. */
		sscanf(line, "%ms %ms", &device, &mt_pt);
		found = (strcmp(device, devpath) == 0);
		if (device) free(device);

		if (found) {
			mt_pt_copy = strdup(mt_pt);
			free(mt_pt);
			break;
		}
	}

	if (line) free(line);
	fclose(mount_fp);

	return mt_pt_copy;
}

/*
 * Waits for the user to unmount given device.
 *
 * Return 1 when given device is unmounted, else return 0.
 */
int has_unmounted(const char *devpath)
{
	FILE *f = fopen(PROC_MOUNTS, "r");
	if (! f) {
		log_fn("Cannot open \"%s\" for reading.", PROC_MOUNTS);
		return 0;
	}

	struct pollfd fds[1];
	fds[0].fd = fileno(f);
	fds[0].events = POLLPRI;

	while (1) {
		int change;

		/* BLOCK till device is unmounted. */
		change = poll(fds, 1, -1);
		if (change == -1) {
			log_fn("%s", strerror(errno));
			return 0;
		}

		if (! is_mounted(devpath)) {
			fclose(f);
			return 1;
		}
	}
}
