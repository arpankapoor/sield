#ifndef _SIELD_LOG_H_
#define _SIELD_LOG_H_

#include <stdarg.h>
#include <libudev.h>

#define log_fn(format, ...) _log_fn(format"\n", ##__VA_ARGS__)
void _log_fn(const char *format, ...);

void log_block_device_info(struct udev_device *device,
                           struct udev_device *parent);

void udev_custom_log_fn(struct udev *udev, int priority, const char *file,
                        int line, const char *fn, const char *format,
                        va_list args);

#endif
