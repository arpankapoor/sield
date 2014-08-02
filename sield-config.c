#define _GNU_SOURCE     /* getline() */
#define _BSD_SOURCE     /* strsep() */
#include <ctype.h>      /* isspace() */
#include <errno.h>      /* errno */
#include <stdio.h>      /* fopen() */
#include <stdlib.h>     /* free() */
#include <string.h>     /* strsep(), strcmp() */

#include "sield-config.h"
#include "sield-log.h"  /* log_fn() */

static const char *CONFIG_FILE = "/etc/sield/sield.conf";

static char *strip_whitespace(char *str);
static char *seperate_line_into_name_value(char **line, const char *delim);
static char *get_sield_attr_base(const char *name, int log);

/*
 * Return pointer to string without trailing whitespace or whitespace at
 * the beginning of the string.
 *
 * Return NULL if string is NULL or entire string consists of whitespace.
 */
static char *strip_whitespace(char *str)
{
    char *ret = NULL;

    if (str == NULL) return NULL;

    /* Remove whitespace from the beginning of the string. */
    while (*str != '\0' && isspace(*str)) str++;

    /* Entire line is whitespace */
    if (*str == '\0') return NULL;

    /* First non-whitespace character */
    ret = str;

    /* Move to the end of the string */
    while (*str != '\0') str++;
    str--;

    /* Move backwards until a non-whitespace character is found. */
    while (isspace(*str)) str--;
    str++;

    *str = '\0';
    return ret;
}

/*
 * Seperate given line into 2 parts using given delimiter and
 * remove any trailing or beginning whitespace from both of them.
 *
 * Return attribute name.
 * The argument given will point to the attribute value.
 */
static char *seperate_line_into_name_value(char **line, const char *delim)
{
    char *name = strsep(line, delim);
    char *value = strsep(line, "\n");

    name = strip_whitespace(name);
    value = strip_whitespace(value);

    *line = value;

    return name;
}

/*
 * Return attribute with given name if present, else return NULL.
 *
 * Log any errors if "log" is non-zero.
 *
 * If there are more than 1 lines with given attribute name,
 * the first among them will be used.
 */
static char *get_sield_attr_base(const char *name, int log)
{
    size_t len = 0;
    const char *delim = "=";
    char *value = NULL;
    char *line = NULL;
    FILE *fp = NULL;

    fp = fopen(CONFIG_FILE, "r");
    if (fp == NULL) {
        if (log != 0) log_fn("fopen: %s: %s", CONFIG_FILE, strerror(errno));
        return NULL;
    }

    while (value == NULL
            && getline(&line, &len, fp) != -1) {

        char *line_begin = line;
        char *name_t = NULL;
        char *value_t = NULL;

        /* Skip empty lines and those starting with # (comments) */
        if (line[0] == '#' || line[0] == '\n') continue;

        name_t = seperate_line_into_name_value(&line_begin, delim);
        value_t = line_begin;

        /* strdup() should have a non-null argument. */
        if (strcmp(name_t, name) == 0 && value_t != NULL)
            value = strdup(value_t);
    }

    if (value == NULL && log != 0)
        log_fn("Cannot find configuration for '%s'.", name);

    /* Clean up */
    if (line) free(line);
    fclose(fp);

    return value;
}

/* Get attribute value without logging. */
char *get_sield_attr_no_log(const char *name)
{
    return get_sield_attr_base(name, 0);
}

/* Logging is turned on */
char *get_sield_attr(const char *name)
{
    return get_sield_attr_base(name, 1);
}

/* Convert value of given attribute to an integer */
long int get_sield_attr_int(const char *name)
{
    long int ret = -1;
    char *value_str = NULL;
    char *endptr = NULL;

    value_str = get_sield_attr(name);

    /* Return -1 if not present. */
    if (value_str == NULL) return -1;

    /* Convert to integer. */
    ret = strtol(value_str, &endptr, 10);

    /* The configuration is not written properly. */
    if (*endptr != '\0') {
        log_fn("Non-integer characters in the config \"%s\"", name);
        ret = -1;
    }

    free(value_str);
    return ret;
}

/* Return -1 if attribute value is set to anything other than 0 or 1 */
int get_sield_attr_bool(const char *name)
{
    long int ret = get_sield_attr_int(name);
    if (ret == 1) return 1;
    if (ret == 0) return 0;

    return -1;
}
