#define _BSD_SOURCE         /* DT_FIFO, scandir() */
#define _GNU_SOURCE         /* asprintf() */
#include <dirent.h>         /* opendir() */
#include <errno.h>          /* errno */
#include <fcntl.h>          /* open() */
#include <pwd.h>            /* getpwuid() */
#include <stdio.h>          /* printf() */
#include <stdlib.h>         /* NULL */
#include <string.h>         /* strerror() */
#include <sys/stat.h>       /* open() */
#include <sys/types.h>      /* opendir() */
#include <unistd.h>         /* getuid(), write() */

#include "sield-ipc.h"      /* sharing information */
#include "sield-log.h"      /* log_fn() */
#include "sield-passwd-cli-get.h"   /* get_passwd() */

static char *get_username(uid_t uid);
static int fifo_filter(const struct dirent *ent);

/* Add program name to logging function */
#define log(format, ...) log_fn("[%s] "format, PROGRAM_NAME, ##__VA_ARGS__)

/* Return the username with given user id */
static char *get_username(uid_t uid)
{
    struct passwd *pwd = NULL;
    char *username = NULL;

    errno = 0;
    pwd = getpwuid(uid);
    if (pwd == NULL) {
        log("%s", strerror(errno));
        log("Could not retrieve username for UID %s");
        return NULL;
    }

    username = strdup(pwd->pw_name);

    return username;
}

/* Filter function to select only named pipes. */
static int fifo_filter(const struct dirent *ent)
{
    if (ent->d_type == DT_FIFO) return 1;
    else return 0;
}

int main(int argc, char *argv[])
{
    int fifos = 0, i = 0, choice = 0;
    char *username = NULL;
    char *tty = NULL;
    char *plain_txt_passwd = NULL;
    char *fifo_path = NULL;
    int fd = -1;
    size_t len = 0;
    struct dirent **entries = NULL;
    struct auth_len lengths;        /* Structure to send string lengths */

    PROGRAM_NAME = argv[0];

    /* Who started this program? */
    username = get_username(getuid());
    if (username == NULL) {
        fprintf(stderr, "Can't verify your credentials.\nQuitting...\n");
        goto error;
    }

    /* From which tty? */
    tty = ttyname(STDIN_FILENO);        /* DO NOT free() */

    log("%s executed %s from %s.", username, PROGRAM_NAME, tty);

    /* Check for directory existence */
    if (access(FIFO_DIR, F_OK) == -1) {
        log("%s", strerror(errno));
        log("Could not open %s", FIFO_DIR);
        fprintf(stderr, "No unattended devices.\n");
        goto error;
    }

    fifos = scandir(FIFO_DIR, &entries, fifo_filter, alphasort);

    if (fifos <= 0) {
        if (fifos == -1) log("%s", strerror(errno));
        fprintf(stderr, "No unattended devices.\n");
        goto error;
    }

    /* Print all available devices */
    printf("Devices:\n");

    for (i = 0; i < fifos; i++) {
        printf("%d) %s\n", i+1, entries[i]->d_name);
    }

    /* Ask for choice if more than 1 device exists. */
    if (fifos > 1) {
        printf("Enter your choice: ");
        if (scanf("%d", &choice) != 1) {
            log("Invalid choice given.\n");
            fprintf(stderr, "Invalid choice.\n");
            goto error;
        }
    } else {
        choice = 0;
    }

    if (asprintf(&fifo_path, "%s%s",
                 FIFO_DIR, entries[choice]->d_name) == -1) {
        log("asprintf: memory error");
        fprintf(stderr, "Memory error");
        goto error;
    }

    /* Write only, non-blocking open */
    fd = open(fifo_path, O_WRONLY | O_NONBLOCK);
    if (fd == -1) {
        /* Read fifo(7) */
        if (errno == ENXIO) {
            log("Another user may be using sld.");
            fprintf(stderr, "Device currently unavailable. Try again.\n");
            goto error;
        }
        log("fopen: %s", strerror(errno));
        log("Unable to open %d for writing.", fifo_path);
        fprintf(stderr, "Could not open given choice.\n");
        goto error;
    }

    /* Ask for password */
    printf("password: ");
    if (get_passwd(&plain_txt_passwd, &len, stdin) == -1) {
        log("Unable to get password from user.");
        fprintf(stderr, "Unable to get password. Quitting...\n");
        close(fd);
        goto error;
    }

    printf("\n");

    /* Set all string lengths */
    lengths.tty_len = strlen(tty + 5);
    lengths.user_len = strlen(username);
    lengths.pwd_len = strlen(plain_txt_passwd);

    /* Send data to daemon */
    if ((write(fd, &lengths, sizeof(struct auth_len))
               != sizeof(struct auth_len))
        /* sizeof(char) is ALWAYS 1 */
        || (write(fd, tty + 5, lengths.tty_len + 1) != lengths.tty_len + 1)
        || (write(fd, username, lengths.user_len + 1) != lengths.user_len + 1)
        || (write(fd, plain_txt_passwd, lengths.pwd_len + 1)
                  != lengths.pwd_len + 1)) {

        log("Failed to send data to daemon.\n");
        fprintf(stderr, "Failed to send data to daemon.\n");
        close(fd);
        goto error;
    }

    if (plain_txt_passwd) free(plain_txt_passwd);
    if (username) free(username);
    if (fifo_path) free(fifo_path);
    for (i = 0; i < fifos; i++) {
        if (entries[i]) free(entries[i]);
    }
    if (entries) free(entries);
    close(fd);

    exit(EXIT_SUCCESS);
error:
    if (plain_txt_passwd) free(plain_txt_passwd);
    if (username) free(username);
    if (fifo_path) free(fifo_path);
    for (i = 0; i < fifos; i++) {
        if (entries[i]) free(entries[i]);
    }
    if (entries) free(entries);
    exit(EXIT_FAILURE);
}
