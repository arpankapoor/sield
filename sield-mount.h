#ifndef _SIELD_MOUNT_H_
#define _SIELD_MOUNT_H_

#include <libudev.h>

/*
 * Mount device.
 */
char *mount_device(struct udev_device *device, int ro);

#endif
