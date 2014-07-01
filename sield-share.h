#ifndef _SIELD_SHARE_H_
#define _SIELD_SHARE_H_

int samba_share(const char *path,
	const char *manufacturer, const char *product);

int restore_smb_conf(void);

#endif
