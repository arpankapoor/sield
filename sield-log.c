#define _GNU_SOURCE     /* strdup() */
#include <libudev.h>
#include <stdarg.h>     /* va_list() */
#include <stdio.h>      /* fprintf() */
#include <stdlib.h>     /* free() */
#include <string.h>     /* strdup() */
#include <time.h>       /* strftime() */

#include "sield-log.h"
#include "sield-config.h"   /* get_sield_attr_no_log() */

static const char *LOGFILE = "/var/log/sield.log";

static FILE *open_log_file(void);
static void write_timestamp(FILE *fp);

static FILE *open_log_file(void)
{
    char *logfile = get_sield_attr_no_log("log file");
    if (logfile == NULL) logfile = strdup(LOGFILE);

    FILE *log_fp = fopen(logfile, "a");
    if (logfile != NULL) free(logfile);
    return log_fp;
}

#define TIME_STR_BUFFER 25
/*
 * Write current system time in the format "[%Y-%m-%d %H:%M] "
 * to given file stream.
 */
static void write_timestamp(FILE *fp)
{
    if (fp == NULL) return;

    time_t timer = time(NULL);
    char current_time[TIME_STR_BUFFER];
    strftime(current_time, TIME_STR_BUFFER, "[%F %T] ", localtime(&timer));

    fprintf(fp, "%s", current_time);
}

/*
 * Write given message to log file.
 */
void _log_fn(const char *format, ...)
{
    FILE *log_fp = open_log_file();
    if (log_fp == NULL) return;

    write_timestamp(log_fp);

    va_list arg;
    va_start(arg, format);
    vfprintf(log_fp, format, arg);
    va_end(arg);
    fclose(log_fp);
}

void log_block_device_info(struct udev_device *device,
                           struct udev_device *parent)
{
    if ((device == NULL) || (parent == NULL)) return;

    log_fn("Device identified.\n"
           "----------------------------------------"
           "----------------------------------------\n"
           "DEVICE INFORMATION\n"
           "==================\n"
           "Vendor ID = %s\n"
           "Product ID = %s\n"
           "Serial Number = %s\n"
           "Manufacturer = %s\n"
           "Product = %s\n"
           "Product version = %s\n"
           "USB version = %s\n"
           "Device node = %s\n"
           "File system = %s\n"
           "----------------------------------------"
           "----------------------------------------",
           udev_device_get_sysattr_value(parent, "idVendor"),
           udev_device_get_sysattr_value(parent, "idProduct"),
           udev_device_get_sysattr_value(parent, "serial"),
           udev_device_get_sysattr_value(parent, "manufacturer"),
           udev_device_get_sysattr_value(parent, "product"),
           udev_device_get_sysattr_value(parent, "bcdDevice"),
           udev_device_get_sysattr_value(parent, "version"),
           udev_device_get_devnode(device),
           udev_device_get_property_value(device, "ID_FS_TYPE"));
}

void udev_custom_log_fn(struct udev *udev, int priority, const char *file,
                        int line, const char *fn, const char *format,
                        va_list args)
{
    FILE *log_fp = open_log_file();
    if (log_fp == NULL) return;

    write_timestamp(log_fp);
    fprintf(log_fp, "[libudev] [%s] ", fn);
    vfprintf(log_fp, format, args);

    fclose(log_fp);
}
