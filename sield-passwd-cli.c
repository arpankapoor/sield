#define _GNU_SOURCE     /* asprintf() */
#include <errno.h>      /* errno */
#include <stdio.h>      /* fprintf() */
#include <stdlib.h>     /* free() */
#include <string.h>     /* strerror() */
#include <sys/types.h>  /* mkfifo() */
#include <sys/stat.h>   /* mkdir() */
#include <utmp.h>       /* setutent() */ 

#include "sield-config.h"   /* get_sield_attr_int() */
#include "sield-ipc.h"      /* IPC struct */
#include "sield-log.h"      /* log_fn() */
#include "sield-passwd-check.h"     /* is_passwd_correct() */
#include "sield-passwd-cli.h"

static const char *PROGRAM_NAME = "sld";
static const char *FIFO_DIR = "/tmp/sld/";

static int notify_tty(const char *tty, const char *manufacturer,
                      const char *product, const char *devnode);
static int notify_all_ttys(const char *manufacturer, const char *product,
                           const char *devnode);
static char *makefifo(const char *manufacturer, const char *product,
                      const char *devnode);

/*
 * Notify user at given tty about device insertion.
 *
 *  0 => SUCCESS
 * -1 => FAILURE
 */
static int notify_tty(const char *tty, const char *manufacturer,
                      const char *product, const char *devnode)
{
    FILE *tty_fp = NULL;
    char *tty_path = NULL;

    if (asprintf(&tty_path, "/dev/%s", tty) == -1) {
        log_fn("asprintf: memory error");
        return -1;
    }

    tty_fp = fopen(tty_path, "w");
    if (tty_fp == NULL) {
        log_fn("fopen: %s", strerror(errno));
        log_fn("Unable to write to %s.", tty);
        return -1;
    }

    fprintf(tty_fp, "%s %s (%s) inserted. To scan and mount, execute %s\n",
            manufacturer, product, devnode, PROGRAM_NAME);

    if (tty_path) free(tty_path);
    fclose(tty_fp);
    return 0;
}

/*
 * Notify all available ttys about device insertion.
 *
 * Return the number of ttys notified.
 */
static int notify_all_ttys(const char *manufacturer, const char *product,
                           const char *devnode)
{
    struct utmp *ut = NULL;
    int ttys_notified = 0;

    setutent();
    /* Don't free ut, it is statically allocated. */
    while ((ut = getutent()) != NULL) {
        /* Skip invalid entries. */
        if (ut->ut_type != USER_PROCESS) continue;

        if (notify_tty(ut->ut_line, manufacturer, product, devnode) == -1) {
            log_fn("Could not notify %s (@%s) about device %s (%s %s).",
                    ut->ut_user, ut->ut_line, devnode, manufacturer, product);
        } else {
            log_fn("Notified %s (@%s) about device %s (%s %s).",
                    ut->ut_user, ut->ut_line, devnode, manufacturer, product);
            ttys_notified++;
        }
    }
    endutent();

    return ttys_notified;
}

/* Return the path of the named pipe constructed. */
static char *makefifo(const char *manufacturer, const char *product,
                      const char *devnode)
{
    mode_t dir_perm, file_perm;
    char *fifo_path = NULL;

    /* FIFO_DIR should be readable, and searchable to all users. */
    dir_perm = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;

    /* FIFOs should not be world readable, but world writable. */
    file_perm = S_IRUSR | S_IWUSR | S_IWGRP | S_IWOTH;

    /* Create FIFO_DIR to place the named pipes. */
    if (mkdir(FIFO_DIR, dir_perm) == -1 && errno != EEXIST) {
        log_fn("mkdir: %s", strerror(errno));
        log_fn("Unable to create directory %s.", FIFO_DIR);
        return NULL;
    }

    /*
     * FIFO name
     *
     * devnode + 5 => File names can't have backslashes
     */
    if (asprintf(&fifo_path, "%s%s %s (%s)",
                 FIFO_DIR, manufacturer, product, devnode + 5) == -1) {
        log_fn("asprintf: memory error");
        return NULL;
    }

    /* Create the named pipe. */
    if (mkfifo(fifo_path, file_perm) == -1) {
        log_fn("mkfifo: %s", strerror(errno));
        log_fn("Unable to create named pipe %s.", fifo_path);
        if (fifo_path) free(fifo_path);
        return NULL;
    }

    return fifo_path;
}

int ask_passwd_cli(const char *manufacturer, const char *product,
                   const char *devnode)
{
    int i = 0;
    int ttys_notified = 0;
    int MAX_PWD_ATTEMPTS = 0;
    int passwd_match = 0;
    char *tty = NULL;
    char *username = NULL;
    char *plain_txt_passwd = NULL;
    char *fifo_path = NULL;
    FILE *fp = NULL;
    struct auth_len lengths;
    
    MAX_PWD_ATTEMPTS = get_sield_attr_int("max password tries");
    if (MAX_PWD_ATTEMPTS == -1) MAX_PWD_ATTEMPTS = 3;

    ttys_notified = notify_all_ttys(manufacturer, product, devnode);

    if (ttys_notified == 0) {
        log_fn("No users are logged in. Ignoring %s (%s %s).",
               devnode, manufacturer, product);
        return 0;
    }

    log_fn("Wrote to %d tty(s) about device %s (%s %s). Awaiting response.",
            ttys_notified, devnode, manufacturer, product);

    fifo_path = makefifo(manufacturer, product, devnode);
    if (fifo_path == NULL) return 0;

    for (i = 0; (i < MAX_PWD_ATTEMPTS) && (passwd_match != 1); i++) {
        /* Open the named pipe for reading. */
        fp = fopen(fifo_path, "r");
        if (fp == NULL) {
            log_fn("fopen: %s", strerror(errno));
            log_fn("Unable to open %s for reading.", fifo_path);
            if (fifo_path) free(fifo_path);
            continue;
        }

        /* Lengths */
        if (fread(&lengths, sizeof(struct auth_len), 1, fp) != 1) {
            log_fn("Unable to read data (strlens) sent from CLI app.");
            continue;
        }

        tty = malloc((lengths.tty_len + 1) * sizeof(char));
        username = malloc((lengths.user_len + 1) * sizeof(char));
        plain_txt_passwd = malloc((lengths.pwd_len + 1) * sizeof(char));

        if ((fread(tty, sizeof(char),
                  lengths.tty_len + 1, fp) != lengths.tty_len + 1)
            || (fread(username, sizeof(char),
                     lengths.user_len + 1, fp) != lengths.user_len + 1)
            || (fread(plain_txt_passwd, sizeof(char),
                     lengths.pwd_len + 1, fp) != lengths.pwd_len + 1)) {

            log_fn("Unable to read data sent from CLI app.");
            if (tty) free(tty);
            if (username) free(username);
            if (plain_txt_passwd) free(plain_txt_passwd);
            fclose(fp);
            continue;
        }

        if (is_passwd_correct(plain_txt_passwd)) {
            log_fn("%s (@%s) provided correct password.", username, tty);
            passwd_match = 1;
        } else {
            log_fn("%s (@%s) entered incorrect password. Attempt #%d",
                   username, tty, i+1);
            passwd_match = 0;
        }

        if (tty) free(tty);
        if (username) free(username);
        if (plain_txt_passwd) free(plain_txt_passwd);
        fclose(fp);
    }

    if (passwd_match == 0) {
        log_fn("Used all password attempts.");
    }

    /* Delete the associated named pipe. */
    if (remove(fifo_path) == -1) {
        log_fn("Unable to delete named pipe %s", fifo_path);
    }
    if (remove(FIFO_DIR) == -1) {
        log_fn("Couldn't delete directory %s", FIFO_DIR);
    }
    if (fifo_path) free(fifo_path);
    return passwd_match;
}
