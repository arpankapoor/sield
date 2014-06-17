#define _GNU_SOURCE		/* getline() */
#define _BSD_SOURCE		/* strsep() */
#include <stdio.h>
#include <stdlib.h>		/* free() */
#include <string.h>		/* strsep(), strcmp() */

#include "sield-config.h"
#include "sield-log.h"


static const char *config_file = "/etc/sield.conf";
static const char *config_file_new = "/etc/sield.conf.new";

static char *strip_whitespace(char *str);
static char *seperate_line_into_name_value(
		char **line, const char *delim);
char *get_sield_attr(const char *name);
static int remove_sield_attr(const char *name);
int set_sield_attr(const char *name, const char *value);

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
 * If there are more than 1 lines with given attribute name,
 * the first among them will be used.
 */
char *get_sield_attr(const char *name)
{
	FILE *config_fp = fopen(config_file, "r");
	if (! config_fp) {
		log_fn("Unable to open config file for reading.");
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

	if (! value) log_fn("Cannot find configuration for %s.", name);

	/* Clean up */
	if (line) free(line);
	fclose(config_fp);

	return value;
}

/*
 * Remove all occurrences of given attribute from the config file.
 *
 * Return 1 on success, else return 0.
 */
static int remove_sield_attr(const char *name)
{
	FILE *config_fp = fopen(config_file, "r");
	if (! config_fp) {
		log_fn("Unable to open config file for reading.");
		return 0;
	}

	FILE *config_fp_new = fopen(config_file_new, "w");
	if (! config_fp_new) {
		log_fn("Unable to create file %s.", config_file_new);
		return 0;
	}

	const char *delim = "=";
	char *value = NULL;
	char *line = NULL;
	size_t len = 0;

	while (! value
		&& getline(&line, &len, config_fp) != -1) {

		/* Write empty lines and comments as is. */
		if (line[0] == '#' || line[0] == '\n') {
			fprintf(config_fp_new, "%s", line);
			continue;
		}

		char *line_ptr = line;

		char *name_t = seperate_line_into_name_value(&line_ptr, delim);

		/* Skip lines that describe given attribute. */
		if (! strcmp(name_t, name)) continue;

		fprintf(config_fp_new, "%s", line);
	}

	/* Clean up */
	if (line) free(line);
	fclose(config_fp);
	fclose(config_fp_new);

	/* Replace with new file. */
	int suc = rename(config_file_new, config_file);

	/* rename(3) returns 0 on success. */
	return ! suc;
}

/*
 * Set the value of given attribute name.
 *
 * Remove any occurrence of given attribute (if present)
 * before setting new value.
 *
 * Return 1 if writing attribute was successful,
 * else return 0.
 */
int set_sield_attr(const char *name, const char *value)
{
	/* Remove all occurrences of the given attribute if present. */
	char *prev_value = get_sield_attr(name);
	if (prev_value) {
		remove_sield_attr(name);
		free(prev_value);
	}

	FILE *config_fp = fopen(config_file, "a");
	if (! config_fp) {
		log_fn("Unable to open config file for appending.");
		return 0;
	}

	/* Ensure that we are on a new line before writing. */
	fprintf(config_fp, "\n%s = %s\n", name, value);

	fclose(config_fp);
	return 1;
}
