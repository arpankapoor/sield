#define _GNU_SOURCE		/* getline() */
#define _BSD_SOURCE		/* strsep() */
#include <errno.h>		/* strerror() */
#include <stdio.h>
#include <stdlib.h>		/* free() */
#include <string.h>		/* strsep(), strcmp() */

#include "sield-config.h"
#include "sield-log.h"

static const char *config_file = "/etc/sield.conf";

static char *strip_whitespace(char *str);
static char *seperate_line_into_name_value(
		char **line, const char *delim);
static char *get_sield_attr_base(const char *name, int log);
char *get_sield_attr(const char *name);
char *get_sield_attr_no_log(const char *name);
long int get_sield_attr_int(const char *name);

/*
 * Return pointer to string without trailing or whitespace at
 * the beginning of the string.
 *
 * Return NULL if string is NULL or
 * entire string consists of whitespace.
 */
static char *strip_whitespace(char *str)
{
	if (! str) return NULL;

	/* Remove whitespace from the beginning of the string. */
	while (*str != '\0' && (*str == ' ' || *str == '\t')) str++;

	/* Entire line is whitespace */
	if (*str == '\0') return NULL;

	/* Return string begins here. */
	char *ret = str;

	/* Move to the end of the string. */
	while (*str != '\0') str++;
	str--;

	/* Move backwards until a non-whitespace character is found. */
	while (*str == ' ' || *str == '\t') str--;
	str++;

	*str = '\0';
	return ret;
}

/*
 * Seperate given line into 2 parts using given delimiter and
 * remove any trailing or beginning whitespace from both of them.
 *
 * Return attribute name.
 *
 * The argument given will point to the attribute value.
 */
static char *seperate_line_into_name_value(
	char **line, const char *delim)
{
	char *name = strsep(line, delim);
	char *value = strsep(line, "\n");

	name = strip_whitespace(name);
	value = strip_whitespace(value);

	*line = value;

	return name;
}

/*
 * Return attribute with given name if present,
 * else return NULL.
 *
 * Log any errors if "log" is non-zero.
 *
 * If there are more than 1 lines with given attribute name,
 * the first among them will be used.
 */
static char *get_sield_attr_base(const char *name, int log)
{
	FILE *config_fp = fopen(config_file, "r");
	if (! config_fp) {
		if (log) {
			log_fn("fopen: %s", strerror(errno));
			log_fn("Unable to open config file for reading.");
		}
		return NULL;
	}

	const char *delim = "=";
	char *value = NULL;
	char *line = NULL;
	size_t len = 0;

	while (! value
		&& getline(&line, &len, config_fp) != -1) {

		/* Skip empty lines and those starting with # (comments) */
		if (line[0] == '#' || line[0] == '\n') continue;

		char *line_ptr = line;

		char *name_t = seperate_line_into_name_value(&line_ptr, delim);
		char *value_t = line_ptr;

		/* strdup() should have a non-null argument. */
		if (! strcmp(name_t, name) && value_t) value = strdup(value_t);
	}

	if (! value && log) log_fn("Cannot find configuration for \"%s\".", name);

	/* Clean up */
	if (line) free(line);
	fclose(config_fp);

	return value;
}

/*
 * Get attribute value without logging.
 */
char *get_sield_attr_no_log(const char *name)
{
	return get_sield_attr_base(name, 0);
}

/*
 * Logging is turned on.
 */
char *get_sield_attr(const char *name)
{
	return get_sield_attr_base(name, 1);
}

/*
 * Convert value of given attribute to int.
 */
long int get_sield_attr_int(const char *name)
{
	char *value_str = get_sield_attr(name);

	/* Return -1 if not present. */
	if (! value_str) return -1;

	char *endptr;

	/* Convert to integer. */
	long int value = strtol(value_str, &endptr, 10);

	/* The configuration is not written properly. */
	if (*endptr != '\0') {
		log_fn("Non-integer characters in the config \"%s\"", name);
		value = -1;
	}

	free(value_str);
	return value;
}

/* Return -1 if attribute value is set to anything other than 0 or 1 */
int get_sield_attr_bool(const char *name)
{
    long int ret = get_sield_attr_int(name);
    if (ret == 1) return 1;
    if (ret == 0) return 0;

    return -1;
}
