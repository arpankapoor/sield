#define _GNU_SOURCE     /* asprintf(), getline(), strdup() */
#include <errno.h>		/* errno */
#include <libudev.h>
#include <poll.h>
#include <stdio.h>      /* fopen(), asprintf() */
#include <stdlib.h>     /* free() */
#include <string.h>     /* strcmp(), strdup() */
#include <sys/mount.h>		/* mount() */
#include <sys/stat.h>		/* mkdir() */

#include "sield-config.h"
#include "sield-log.h"
#include "sield-mount.h"

static const char *PROC_MOUNTS = "/proc/mounts";

static char *get_mount_point_attr(struct udev_device *device);

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

/*
 * Given a device node file name,
 * return its mount point from the PROC_MOUNTS file.
 *
 * Return NULL if not mounted.
 */
char *get_mountpoint(const char *devnode)
{
    size_t len = 0;
    char *mountpoint = NULL;
    char *line = NULL;
    FILE *fp = NULL;

    fp = fopen(PROC_MOUNTS, "r");
    if (fp == NULL) {
        log_fn("fopen(): %s: %s", PROC_MOUNTS, strerror(errno));
        return NULL;
    }

    while (getline(&line, &len, fp) != -1
            && mountpoint == NULL) {
        char *dev = NULL;
        char *mtpt = NULL;

        /* %m modifier for dynamic string allocation. */
        sscanf(line, "%ms %ms", &dev, &mtpt);

        /* Is this the device we are looking for? */
        if (strcmp(dev, devnode) == 0 && mtpt != NULL)
            mountpoint = strdup(mtpt);

        if (dev) free(dev);
        if (mtpt) free(mtpt);
    }

    if (line) free(line);
    fclose(fp);

    return mountpoint;
}

/*
 * Wait until given device node file is unmounted.
 *
 * Return 1 when given device is unmounted, else return 0.
 */
int has_unmounted(const char *devnode)
{
    struct pollfd fds[1];
    FILE *fp = NULL;

    fp = fopen(PROC_MOUNTS, "r");
    if (fp == NULL) {
        log_fn("fopen(): %s: %s", PROC_MOUNTS, strerror(errno));
        return 0;
    }

    fds[0].fd = fileno(fp);
    fds[0].events = POLLPRI;

    while (1) {
        int change;
        char *mountpoint = NULL;

        /* BLOCK till device is unmounted. */
        change = poll(fds, 1, -1);
        if (change == -1) {
            log_fn("poll(): %s", strerror(errno));
            return 0;
        }

        mountpoint = get_mountpoint(devnode);
        if (mountpoint != NULL) {
            free(mountpoint);
            fclose(fp);
            return 1;
        }
    }
}
