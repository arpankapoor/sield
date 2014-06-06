#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>	/* va_list */
#include <string.h>
#include <libudev.h>
#include <time.h>
/*#include <locale.h>
#include <unistd.h>
#include <sys/mount.h> */

/**************************** LOGGING ******************************/

const char *LOG_FILE = "/var/log/sield.log";

FILE *open_log_file(void)
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

void close_log_file(FILE *LOG_FP)
{
	if (fclose(LOG_FP) != 0) {
#ifdef DEBUG
		fprintf(stderr, "Unable to close log file.\n");
#endif
	}
}

/* Write current system time in the format "[%Y-%m-%d %H:%M] "
 * to given file stream. */
void write_timestamp(FILE *fp)
{
	if (!fp) return;

	time_t timer = time(NULL);
	char current_time[20];
	strftime(current_time, 20, "[%F %R] ", localtime(&timer));

	fprintf(fp, current_time);
}

/* Write message along with a newline to the LOG_FILE */
#define log_fn(format, ...) _log_fn(format"\n", ##__VA_ARGS__)
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

/********************************************************************/


/*********************** UDEV EXTENSIONS ****************************/

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

/********************************************************************/

/* Return a listening udev_monitor with given
 * event source, subsystem and device type. */
struct udev_monitor *monitor_device_with_subsytem_devtype(
	struct udev *udev, const char *event_source,
	const char *subsystem, const char *devtype)
{
	struct udev_monitor *monitor = udev_monitor_new_from_netlink(
					udev, event_source);
	if (!monitor) {
		log_fn("Failed to setup a new udev_monitor.");
		return NULL;
	}

	int rt;
	rt = udev_monitor_filter_add_match_subsystem_devtype(
		monitor, subsystem, devtype);
	if (rt != 0) {
		log_fn("Failed to setup monitor filter.");
		return NULL;
	}

	rt = udev_monitor_enable_receiving(monitor);
	if (rt != 0) {
		log_fn("Failed to bind udev_monitor to event source.");
		return NULL;
	}

	return monitor;
}

/* Return a udev_device with given action, else return NULL */
struct udev_device *receive_device_with_action(
	struct udev_monitor *monitor, const char *action)
{
	/* udev_monitor_receive_device is NONBLOCKING */
	struct udev_device *device = udev_monitor_receive_device(monitor);
	if (device) {
		const char *actual_action = udev_device_get_action(device);
		if (strcmp(actual_action, action) == 0) return device;
	}

	return NULL;
}

int main(int argc, char **argv)
{
	struct udev *udev = udev_new();
	udev_set_log_fn(udev, udev_custom_log_fn);

	/* Monitor block devices */
	struct udev_monitor *monitor = monitor_device_with_subsytem_devtype(
					udev, "udev", "block", NULL);
	if (!monitor) exit(EXIT_FAILURE);

	while (1) {
		/* Receive udev_device for any "block" device which was
		 * plugged in ("add"ed) to the system. */
		struct udev_device *device = receive_device_with_action(
						monitor, "add");

		/* The device should be using USB */
		struct udev_device *parent = udev_device_get_parent_with_subsystem_devtype(
						device, "usb", "usb_device");

		if (device && parent) {
			const char *devtype = udev_device_get_devtype(device);

			printf("%s %s inserted ",
				udev_device_get_sysattr_value(parent, "manufacturer"),
				udev_device_get_sysattr_value(parent, "product"));

			if (strcmp(devtype, "disk") == 0) {
				printf ("with device node %s.\n",
					udev_device_get_devnode(device));
			} else if (strcmp(devtype, "partition") == 0) {
				printf ("with partition %s.\n",
					udev_device_get_devnode(device));
			}

			udev_device_unref(device);
		}
	}

	udev_monitor_unref(monitor);
	udev_unref(udev);
	return 0;
}
