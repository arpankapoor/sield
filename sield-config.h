#ifndef _SIELD_CONFIG_H_
#define _SIELD_CONFIG_H_

/*
 * Retrieve an attribute from the config file.
 */
char *get_sield_attr(const char *name);
long int get_sield_attr_int(const char *name);

/*
 * Set an attribute.
 */
int set_sield_attr(const char *name, const char *value);

#endif
