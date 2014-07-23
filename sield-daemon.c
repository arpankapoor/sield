#include <fcntl.h>          /* open() */
#include <stdlib.h>         /* exit() */
#include <sys/stat.h>       /* umask() */
#include <unistd.h>         /* fork(), setsid(), access() */
#include "sield-daemon.h"
#include "sield-log.h"      /* log_fn() */
#include "sield-pid.h"      /* write_pidfile(), ... */

#define MAX_OPEN 8192       /* wild guess at number of open file descriptors */

/* Become a SysV daemon */
int become_daemon(void)
{
    int fd;
    long maxfd, i;

    switch (fork()) {
        case -1: return -1;             /* error */
        case 0: break;                  /* child process created */
        default: exit(EXIT_FAILURE);    /* parent receives child's PID */
    }

    /* Detach from any terminal and create an independent session. */
    if (setsid() == -1) return -1;

    /* Ensure that the daemon can never re-acquire a terminal again. */
    switch (fork()) {
        case -1: return -1;
        case 0: break;
        default: exit(EXIT_FAILURE);
    }

    /* Reset file mode creation mask. */
    umask(0);

    /* Change current directory to root directory (/) */
    if (chdir("/") == -1) return -1;

    /* Find maximum open file descriptors */
    maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd == -1) maxfd = MAX_OPEN;

    /* Close all open file descriptors */
    for (i = 0; i < maxfd; i++) close(i);

    /* Connect /dev/null to stdin, stdout, stderr */
    close(STDIN_FILENO);

    fd = open("/dev/null", O_RDWR);
    if (fd != STDIN_FILENO) return -1;
    if (dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO) return -1;
    if (dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO) return -1;

    /* Write PID file in /var/run/ */
    if (write_pidfile() == -1) return -1;

    return 0;
}
