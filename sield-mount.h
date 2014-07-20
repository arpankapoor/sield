#ifndef _SIELD_MOUNT_H_
#define _SIELD_MOUNT_H_

#include <libudev.h>

char *mount_device(struct udev_device *device, int ro);
int unmount(const char *target);
int is_mounted(const char *devpath);
char *get_mountpoint(const char *devpath);
int has_unmounted(const char *devpath);

#endif
