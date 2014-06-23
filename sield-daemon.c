#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>		/* umask(), open() */
#include <unistd.h>		/* fork(), _exit(), setsid(), chdir() */

#include "sield-daemon.h"

#define BD_MAX_CLOSE 8192
/*
 * Make the calling process a SysV daemon.
 *
 * Return -1 on error.
 */
int become_daemon(void)
{
	int maxfd, fd;

	switch (fork()) {		/* Become backgroud process */
	case -1: return -1;
	case 0: break;			/* Child falls through... */
	default: _exit(EXIT_SUCCESS);	/* while parent terminates */
	}

	/* Become leader of new session */
	if (setsid() == -1)
		return -1;

	switch (fork()) {
	case -1: return -1;
	case 0: break;
	default: _exit(EXIT_SUCCESS);
	}

	/* Clear file mode creation mask */
	umask(0);

	/* Change to root directory */
	chdir("/");

	/* Close all open files */
	maxfd = sysconf(_SC_OPEN_MAX);
	if (maxfd == -1)
		maxfd = BD_MAX_CLOSE;

	for (fd = 0; fd < maxfd; fd++)
		close(fd);


	/* Reopen standard fd's to /dev/null */
	close(STDIN_FILENO);

	fd = open("/dev/null", O_RDWR);

	if (fd != STDIN_FILENO)
		return -1;

	if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO)
		return -1;

	if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
		return -1;

	return 0;
}
