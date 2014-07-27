#define _GNU_SOURCE         /* asprintf() */
#include <stdio.h>          /* asprintf() */
#include <stdlib.h>         /* free() */
#include <string.h>         /* strdup() */
#include <unistd.h>         /* access() */

#include "sield-av.h"
#include "sield-config.h"   /* get_sield_attr() */
#include "sield-log.h"      /* log_fn() */

static const char *AVPATH = "/usr/bin/clamscan";
static const char *LOGFILE = "/var/log/sield.log";

/*
 * Scan all files in given directory.
 *
 * Return
 * 0 if no virus detected,
 * 1 if virus is detected, &
 * 2 on error.
 */
int is_infected(const char *dir)
{
    char *avpath = NULL;
    char *logfile = NULL;
    char *cmd = NULL;
    int avresult = 2;

    /* Anti-virus path */
    avpath = get_sield_attr("av path");
    if (avpath == NULL) avpath = strdup(AVPATH);

    /* Check if avpath exists */
    if (access(avpath, F_OK) == -1) {
        log_fn("'avpath' %s doesn't exist. Will mount as read-only.", avpath);
        return 2;
    }

    /* Log file */
    logfile = get_sield_attr("log file");
    if (logfile == NULL) logfile = strdup(LOGFILE);

    if (asprintf(&cmd, "%s -r -l %s %s", avpath, logfile, dir) == -1) {
        log_fn("asprintf(): memory error.");
        return 2;
    }

    log_fn("Starting virus scan on %s using clamscan.", dir);
    avresult = system(cmd);
    log_fn("Virus scan on %s completed.", dir);

    if (avresult == 0) log_fn("No virus found.");
    else if (avresult == 1) log_fn("Virus(es) found.");
    else log_fn("Some error(s) occurred while scanning.");

    free(avpath);
    free(logfile);
    free(cmd);

    return avresult;
}
