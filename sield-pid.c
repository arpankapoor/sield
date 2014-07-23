#include <errno.h>      /* errno */
#include <signal.h>     /* kill() */
#include <stdio.h>      /* fopen(), remove() */
#include <string.h>     /* strerror() */
#include <sys/types.h>  /* kill() */
#include <unistd.h>     /* getpid() */
#include "sield-log.h"
#include "sield-pid.h"

static const char *PIDFILE = "/var/run/sield.pid";

static pid_t getpid_from_pidfile(void);
static int write_to_pidfile(void);

static int write_to_pidfile(void)
{
    FILE *fp = fopen(PIDFILE, "w");
    if (fp == NULL) {
        log_fn("fopen(): %s: %s", PIDFILE, strerror(errno));
        return -1;
    }

    fprintf(fp, "%ld\n", (long int)getpid());
    fclose(fp);

    return 0;
}

int write_pidfile(void)
{
    pid_t pid = -1;

    if (access(PIDFILE, F_OK) == -1) {
        if (write_to_pidfile() == -1) return -1;
    } else {
        pid = getpid_from_pidfile();
        if (pid == -1) return -1;

        /* PID already exists and is running */
        if (kill(pid, 0) == 0) {
            log_fn("Already running. PID %ld", (long int)pid);
            log_fn("Delete %s if you think this is an error.", PIDFILE);
            return -1;
        } else if (write_to_pidfile() == -1) {
            return -1;
        }
    }

    return 0;
}

static pid_t getpid_from_pidfile(void)
{
    long int pid = -1;
    FILE *fp = fopen(PIDFILE, "r");
    if (fp == NULL) {
        log_fn("fopen(): %s: %s", PIDFILE, strerror(errno));
        return -1;
    }

    fscanf(fp, "%ld", &pid);
    fclose(fp);

    return (pid_t)pid;
}

int rm_pidfile(void)
{
    if (remove(PIDFILE) == -1) {
        log_fn("remove(): %s: %s", PIDFILE, strerror(errno));
        return -1;
    }

    return 0;
}
