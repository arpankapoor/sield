#ifndef _SIELD_MOUNT_H_
#define _SIELD_MOUNT_H_

#include <libudev.h>

/*
 * Mount device.
 */
char *mount_device(struct udev_device *device, int ro);

/* Unmount */
int unmount(const char *target);
int is_mounted(const char *devpath);
char *get_mount_point(const char *devpath);
int has_unmounted(const char *devpath);

#endif
