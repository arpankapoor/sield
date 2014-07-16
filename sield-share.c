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
static int write_smbconf(const char *path, const char *manufacturer,
                         const char *product);
static int restart_daemon(const char *name);
static int restart_daemon_alt(const char *name);

/* Write custom smb.conf file and restart samba daemon. */
int samba_share(const char *path, const char *manufacturer,
                const char *product)
{
    if ((write_smbconf(path, manufacturer, product) != 0)
        || (restart_daemon("smbd") != 0)
        || (restart_daemon("nmbd") != 0)) {
        return -1;
    } else {
        return 0;
    }
}

/* Restore original smb.conf */
int restore_smb_conf(void)
{
    if (rename(SMB_FILE_BAK, SMB_FILE) == -1) {
        log_fn("%s", strerror(errno));
        log_fn("Unable to restore smb.conf");
        return -1;
    }

    return 0;
}

/* Backup smb.conf file */
static int backup_smb_file(void)
{
    /*
     * TODO: smb.conf may also reside at
     * 1) /usr/local/samba/lib/smb.conf
     * 2) /usr/samba/lib/smb.conf
     *
     * according to samba(8).
     */
    if (rename(SMB_FILE, SMB_FILE_BAK) == -1) {
        log_fn("%s", strerror(errno));
        log_fn("Unable to backup samba configuration file \"%s\".", SMB_FILE);
        return -1;
    }

    return 0;
}

/*
 * Write smb.conf to share given path
 * (after backing up the old smb.conf)
 *
 * Return 0 on success, -1 on error.
 */
static int write_smbconf(const char *path, const char *manufacturer,
                         const char *product)
{
    char *workgroup = NULL;
    char *hosts_allow = NULL;
    FILE *smb = NULL;

    /* Backup old smb file. */
    if (backup_smb_file() == -1) return -1;

    smb = fopen(SMB_FILE, "w");
    if (smb == NULL) {
        log_fn("Unable to open \"%s\" for writing.", SMB_FILE);
        return -1;
    }

    fprintf(smb, "[global]\n");
    workgroup = get_sield_attr("workgroup");
    if (workgroup != NULL) {
        fprintf(smb, "workgroup = %s\n", workgroup);
        free(workgroup);
    }

    hosts_allow = get_sield_attr("hosts allow");
    if (hosts_allow != NULL) {
        fprintf(smb, "hosts allow = %s\n", get_sield_attr("hosts allow"));
        free(hosts_allow);
    }

    fprintf(smb, "log file = /var/log/samba/log.%%m\n");
    fprintf(smb, "server string = USB Share\n");

    /* Local settings */
    fprintf(smb, "[%s %s]\n", manufacturer, product);
    fprintf(smb, "path = %s\n", path);
    fprintf(smb, "browseable = yes\n");

    fprintf(smb, "read only = ");

    if (get_sield_attr_int("read only") == 0) fprintf(smb, "no\n");
    else fprintf(smb, "yes\n");

    fclose(smb);
    return 0;
}

/*
 * Restart the given daemon.
 *
 * Return 0 on success, else return -1.
 */
static int restart_daemon(const char *name)
{
    pid_t pid = 0;
    char *pid_file = NULL;
    FILE *pid_fp = NULL;

    /*
     * Try sending a SIGHUP to the running process.
     * (find $name.pid in /var/run)
     *
     * if this fails, run "$name restart".
     */
    if (asprintf(&pid_file, "/var/run/%s.pid", name) == -1) {
        log_fn("asprintf(): Memory error");
        return -1;
    }

    pid_fp = fopen(pid_file, "r");
    if (pid_fp == NULL) {
        log_fn("Can't open %s for reading.", pid_file);
        return restart_daemon_alt(name);
    }

    free(pid_file);

    if (fscanf(pid_fp, "%d", &pid) != 1) {
        log_fn("Can't read pid from %s.", pid_file);
        return restart_daemon_alt(name);
    }

    if (kill(pid, SIGHUP) == -1) {
        log_fn("Couldn't send SIGHUP to PID %d: %s", pid, strerror(errno));
        return restart_daemon_alt(name);
    } else {
        log_fn("Sent SIGHUP to PID %d (%s).", pid, name);
        return 0;
    }
}

/*
 * Restart any daemon from sh
 *
 * Return 0 on success, -1 on error.
 */
static int restart_daemon_alt(const char *name)
{
    int ret = -1;
    char *cmd = NULL;
    if (asprintf(&cmd, "%s restart", name) == -1) {
        log_fn("memory error");
        return -1;
    }

    ret = system(cmd);

    if (ret != 0) log_fn("Failed to restart %s.", name);
    else log_fn("Restarted %s.", name);

    free(cmd);
    return ret;
}
