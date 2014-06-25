#define _GNU_SOURCE
#include <clamav.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sield-config.h"
#include "sield-log.h"

static const char *AV_PATH = "/usr/bin/clamscan";
static const char *AV_LOGFILE = "/var/log/sield-av.log";

/*
 * Initialize libclamav for scanning.
 * * Return NULL if any error occurs, else * return the compiled cl_engine.
 */
static struct cl_engine *clam_init(void)
{
	struct cl_engine *engine;
	unsigned int sigs = 0;
	int ret;

	if (! (engine = cl_engine_new())) {
		log_fn("libclamav: Can't create new engine");
		return NULL;
	}

	if ((ret = cl_load(cl_retdbdir(), engine, &sigs, CL_DB_STDOPT)) != CL_SUCCESS) {
		log_fn("libclamav: cl_load: %s", cl_strerror(ret));
		cl_engine_free(engine);
		return NULL;
	}

	if ((ret = cl_engine_compile(engine)) != CL_SUCCESS) {
		log_fn("libclamav: cl_engine_compile(): %s", cl_strerror(ret));
		cl_engine_free(engine);
		return NULL;
	}

	return engine;
}

/*
 * Scan the directory using clamscan.
 */
static int clam_scan(const char *dir)
{
	char *cmd = NULL;

	char *av_logfile = get_sield_attr("av_logfile");
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
	struct cl_engine *engine = clam_init();
	if (! engine) return clam_scan(dir);

	int av_result, ret;
	const char *virus;
	unsigned long int scanned = 0;

	log_fn("Starting virus scan on %s using libclamav.", dir);

	/* TODO: Scan recursively within the directory. */
	av_result = cl_scanfile(dir, &virus, &scanned, engine, CL_SCAN_STDOPT);

	if ((ret = cl_engine_free(engine)) != CL_SUCCESS) {
		log_fn("libclamav: %s", cl_strerror(ret));
		return 2;
	}

	if (av_result == CL_VIRUS) {
		log_fn("Virus detected: %s\n", virus);
		return 1;
	} else {
		log_fn("No virus\n");
		return 0;
	}
}
