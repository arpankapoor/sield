#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sield-config.h"
#include "sield-log.h"

static const char *AV_PATH = "/usr/bin/clamscan";
static const char *AV_LOGFILE = "/var/log/sield-av.log";

/*
 * Scan all files in given directory.
 *
 * Return
 * 0 if no virus detected,
 * 1 if virus is detected, &
 * 2 on error.
 */
int virus_scan(const char *dir)
{
	char *cmd = NULL;

	char *av_logfile = get_sield_attr("av log file");
	if (! av_logfile) av_logfile = strdup(AV_LOGFILE);

	if (asprintf(&cmd, "%s -r -l %s %s",
			AV_PATH, av_logfile, dir) == -1) {
		log_fn("clam_scan: asprintf: memory error.");
		return 2;
	}

	log_fn("Starting virus scan on %s using clamscan.", dir);
	int av_result = system(cmd);
	log_fn("Virus scan on %s completed.", dir);

	if (av_result == 0) {
		log_fn("No virus found.");
	} else if (av_result == 1) {
		log_fn("Virus(es) found. "
			"View %s for more details.", av_logfile);
	} else {
		log_fn("Some error(s) occurred while scanning. "
			"View %s for more details.", av_logfile);
	}

	if (cmd) free(cmd);
	if (av_logfile) free(av_logfile);

	return av_result;
}
