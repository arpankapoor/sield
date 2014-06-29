#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sield-config.h"
#include "sield-log.h"

static const char *SMB_FILE = "/etc/samba/smb.conf";
static const char *SMB_FILE_BAK = "/etc/samba/smb.conf.bak";
static int backup_smb_file(void);
static int write_smbconf(const char *path);
static int restart_daemon(const char *name);
static int restart_daemon_alt(const char *name);
/*
 * Write custom smb.conf file
 * and restart samba daemon.
 */
int samba_share(const char *path)
{
	return write_smbconf(path)
		&& restart_daemon("smbd")
		&& restart_daemon("nmbd");
}

/*
 * Return 1 if smb.conf file is backed up,
 * else return 0.
 */
static int backup_smb_file(void)
{
	/*
	 * TODO: smb.conf may also reside at
	 * 1. /usr/local/samba/lib/smb.conf
	 * 2. /usr/samba/lib/smb.conf
	 */
	if (rename(SMB_FILE, SMB_FILE_BAK) == -1) {
		log_fn("%s", strerror(errno));
		log_fn("Unable to backup samba configuration file \"%s\".", SMB_FILE);
		return 0;
	}

	return 1;
}

/*
 * Write smb.conf to share given path
 * (after backing up the old smb.conf)
 *
 * Return 1 on success, else return 0.
 */
static int write_smbconf(const char *path)
{
	/* Backup old smb file. */
	if (! backup_smb_file()) return 0;

	FILE *smb = fopen(SMB_FILE, "w");
	if (! smb) {
		log_fn("Unable to open \"%s\" for writing.");
		return 0;
	}

	fprintf(smb, "[global]\n");
	char *workgroup = get_sield_attr("workgroup");
	if (workgroup) {
		fprintf(smb, "workgroup = %s\n", workgroup);
		free(workgroup);
	}

	char *hosts_allow = get_sield_attr("hosts allow");
	if (hosts_allow) {
		fprintf(smb, "hosts allow = %s\n", get_sield_attr("hosts allow"));
		free(hosts_allow);
	}
	
	fprintf(smb, "log file = /var/log/samba/log.%%m\n");

	/* Local settings */
	fprintf(smb, "[sield]\n");
	fprintf(smb, "path = %s\n", path);
	fprintf(smb, "browseable = yes\n");

	int ro = get_sield_attr_int("read only");
	fprintf(smb, "read only = ");

	if (ro == 0) fprintf(smb, "no\n");
	else fprintf(smb, "yes\n");

	fclose(smb);
	return 1;
}

/*
 * Restart the given daemon.
 *
 * Return 1 on success, else return 0.
 */
static int restart_daemon(const char *name)
{
	/*
	 * Try sending a SIGHUP to the running process.
	 * (find $name.pid in /run)
	 *
	 * if this fails, run "$name restart".
	 */

	char *pid_file = NULL;
	if (asprintf(&pid_file, "/run/%s.pid", name) == -1) return 0;

	FILE *pid_fp = fopen(pid_file, "r");
	if (! pid_fp) {
		log_fn("Can't open \"%s\" for reading.", pid_file);
		return restart_daemon_alt(name);
	}

	free(pid_file);

	pid_t pid = 0;
	if (fscanf(pid_fp, "%d", &pid) != 1) {
		log_fn("Can't read pid from \"%s\".", pid_file);
		return restart_daemon_alt(name);
	}

	if (kill(pid, SIGHUP) == -1) {
		log_fn("Couldn't send SIGHUP to PID %d: %s", pid, strerror(errno));
		return restart_daemon_alt(name);
	} else {
		log_fn("Sent SIGHUP to PID %d.", pid);
		return 1;
	}
}

/*
 * Restart smbd from sh
 */
static int restart_daemon_alt(const char *name)
{
	char *cmd = NULL;
	if (asprintf(&cmd, "%s restart", name) == -1) {
		log_fn("memory error");
		return 0;
	}

	if (system(cmd) != 0) {
		log_fn("Failed to restart %s.", name);
		free(cmd);
		return 0;
	} else {
		log_fn("Restarted %s.", name);
		free(cmd);
		return 1;
	}
}
