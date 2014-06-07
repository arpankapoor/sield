#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sield.h"

static const char *LOG_FILE = "/var/log/sield.log";

static FILE *open_log_file(void)
{
	FILE *LOG_FP = fopen(LOG_FILE, "a");
	if (!LOG_FP) {
#ifdef DEBUG
		fprintf(stderr, "Unable to open log file.\n");
#endif
		return NULL;
	}

	return LOG_FP;
}

static void close_log_file(FILE *LOG_FP)
{
	if (fclose(LOG_FP) != 0) {
#ifdef DEBUG
		fprintf(stderr, "Unable to close log file.\n");
#endif
	}
}

/* Write current system time in the format "[%Y-%m-%d %H:%M] "
 * to given file stream. */
static void write_timestamp(FILE *fp)
{
	if (!fp) return;

	time_t timer = time(NULL);
	char current_time[20];
	strftime(current_time, 20, "[%F %R] ", localtime(&timer));

	fprintf(fp, current_time);
}

/* Write message along with a newline to the LOG_FILE */
void _log_fn(const char *format, ...)
{
	FILE *LOG_FP = open_log_file();
	if(!LOG_FP) return;

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
	if (!device || !parent) return;
	log_fn("%s identified.\n"
		"Vendor=%s ProdID=%s Rev=%s\n"
		"Manufacturer=%s\n"
		"Product=%s\n"
		"SerialNumber=%s\n"
		"DeviceNode=%s\n"
		"FileSystem=%s\n",
		udev_device_get_devtype(device),
		udev_device_get_sysattr_value(parent, "idVendor"),
		udev_device_get_sysattr_value(parent, "idProduct"),
		udev_device_get_sysattr_value(parent, "bcdDevice"),
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
	if (!LOG_FP) return;

	write_timestamp(LOG_FP);
	fprintf(LOG_FP, "[libudev] [%s] ", fn);
	vfprintf(LOG_FP, format, args);

	close_log_file(LOG_FP);
}