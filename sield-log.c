#define _GNU_SOURCE		/* strdup() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>		/* strdup() */
#include <time.h>

#include "sield-log.h"
#include "sield-config.h"

static FILE *open_log_file(void);
static void close_log_file(FILE *LOG_FP);
static void write_timestamp(FILE *fp);

static FILE *open_log_file(void)
{
	char *LOG_FILE = get_sield_attr_no_log("logfile");
	if (! LOG_FILE) LOG_FILE = strdup("/var/log/sield.log");

	FILE *LOG_FP = fopen(LOG_FILE, "a");
	if (! LOG_FP) {
#ifdef DEBUG
		fprintf(stderr, "Unable to open log file %s.\n", LOG_FILE);
#endif
	}

	free(LOG_FILE);
	return LOG_FP;
}

static void close_log_file(FILE *LOG_FP)
{
	/* fclose() returns 0 on success. */
	if (fclose(LOG_FP)) {
#ifdef DEBUG
		fprintf(stderr, "Unable to close log file.\n");
#endif
	}
}

/* Write current system time in the format "[%Y-%m-%d %H:%M] "
 * to given file stream. */
#define TIME_STR_BUFFER 25
static void write_timestamp(FILE *fp)
{
	if (! fp) return;

	time_t timer = time(NULL);
	char current_time[TIME_STR_BUFFER];
	strftime(current_time, TIME_STR_BUFFER, "[%F %T] ", localtime(&timer));

	fprintf(fp, "%s", current_time);
}

/* Write message along with a newline to the LOG_FILE */
void _log_fn(const char *format, ...)
{
	FILE *LOG_FP = open_log_file();
	if(! LOG_FP) return;

	write_timestamp(LOG_FP);

	va_list arg;
	va_start(arg, format);
	vfprintf(LOG_FP, format , arg);
	va_end(arg);
	close_log_file(LOG_FP);
}

/* Log block device information */
void log_block_device_info(struct udev_device *device,
	struct udev_device *parent)
{
	if (! device || ! parent) return;
	log_fn("%s identified.\n"
		"  DEVICE INFORMATION\n"
		"\tVendor=%s ProdID=%s\n"
		"\tManufacturer=%s\n"
		"\tProduct=%s\n"
		"\tSerial#=%s\n"
		"\tDevNode=%s\n"
		"\tFileSystem=%s\n",
		udev_device_get_devtype(device),
		udev_device_get_sysattr_value(parent, "idVendor"),
		udev_device_get_sysattr_value(parent, "idProduct"),
		udev_device_get_sysattr_value(parent, "manufacturer"),
		udev_device_get_sysattr_value(parent, "product"),
		udev_device_get_sysattr_value(parent, "serial"),
		udev_device_get_devnode(device),
		udev_device_get_property_value(device, "ID_FS_TYPE"));
}

void udev_custom_log_fn(struct udev *udev,
	int priority, const char *file, int line, const char *fn,
	const char *format, va_list args)
{
	FILE *LOG_FP = open_log_file();
	if (! LOG_FP) return;

	write_timestamp(LOG_FP);
	fprintf(LOG_FP, "[libudev] [%s] ", fn);
	vfprintf(LOG_FP, format, args);

	close_log_file(LOG_FP);
}
