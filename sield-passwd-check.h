#ifndef _SIELD_PASSWD_CHECK_H_
#define _SIELD_PASSWD_CHECK_H_

static const char *PASSWD_FILE = "/etc/sield/sield.passwd";
int is_passwd_correct(const char *plain_txt_passwd);

#endif
