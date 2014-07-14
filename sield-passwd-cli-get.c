#define _GNU_SOURCE     /* getline() */
#include <stdio.h>      /* getline() */
#include <termios.h>    /* tcgetattr(), tcsetattr() */

#include "sield-log.h"              /* log_fn() */
#include "sield-passwd-cli-get.h"   /* get_passwd() */

/*
 * Switch off terminal echoing and retrieve password.
 *
 * Return number of characters read (excluding newline)
 * 	OR
 * -1 on error.
 */
ssize_t get_passwd(char **plain_txt_passwd, size_t *n, FILE *stream)
{
    struct termios old, new;
    ssize_t read = 0;

    /* Get old terminal attributes. */
    if (tcgetattr(fileno(stream), &old) == -1) {
        fprintf(stderr, "Unable to GET terminal attributes.");
        log_fn("Unable to GET terminal attributes.");
        return -1;
    }

    new = old;
    new.c_lflag &= ~ECHO;	/* Turn echoing off. */

    if (tcsetattr(fileno(stream), TCSAFLUSH, &new) == -1) {
        fprintf(stderr, "Unable to SET terminal attributes.");
        log_fn("Unable to SET terminal attributes.");
        return -1;
    }

    /* Read password */
    read = getline(plain_txt_passwd, n, stream);

    /* Restore terminal settings. */
    (void) tcsetattr(fileno(stream), TCSAFLUSH, &old);

    /* Change newline to '\0'. */
    if (read > 0) {
        char *passwd = *plain_txt_passwd;
        passwd[read - 1] = '\0';
    }

    return read > 0 ? (read - 1) : read;
}
