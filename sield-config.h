#ifndef _SIELD_CONFIG_H_
#define _SIELD_CONFIG_H_

/*
 * Retrieve an attribute from the config file.
 */
char *get_sield_attr(const char *name);
char *get_sield_attr_no_log(const char *name);
long int get_sield_attr_int(const char *name);
int get_sield_attr_bool(const char *name);

#endif
