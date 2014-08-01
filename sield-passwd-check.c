#define _GNU_SOURCE         /* getline(), strdup(), crypt() */
#include <errno.h>          /* strerror() */
#include <pwd.h>            /* getpwuid() */
#include <shadow.h>         /* getspnam() */
#include <stdio.h>          /* fopen(), getline(), fclose() */
#include <stdlib.h>         /* free() */
#include <string.h>         /* strcmp() */
#include <sys/types.h>      /* getpwuid() */
#include <unistd.h>         /* crypt(), access() */

#include "sield-config.h"   /* get_sield_attr() */
#include "sield-log.h"      /* log_fn() */
#include "sield-passwd-check.h"

static char *get_encrypted_user_passwd(uid_t uid);
static char *get_sield_passwd(void);

/*
 * Check against:
 * 1. Application password, if defined, else
 * 2. Superuser password.
 *
 * Return 1 if password is correct, else return 0.
 */
int is_passwd_correct(const char *plain_txt_passwd)
{
    char *encrypted_passwd_to_check_against = NULL;
    char *salt = NULL;
    char *given_passwd_encrypted = NULL;
    int passwd_match = 0;

    encrypted_passwd_to_check_against = get_sield_passwd();

    if (!encrypted_passwd_to_check_against) {
        log_fn("Application password not set. Trying to use superuser password.");
        encrypted_passwd_to_check_against = get_encrypted_user_passwd(0);
    }

    if (!encrypted_passwd_to_check_against) {
        log_fn("Could not get superuser password.");
        return 0;
    }

    /*
     * salt is a character string starting with the characters "$id$"
     * followed by a string terminated by "$":
     *
     * $id$salt$encrypted
     *
     * Here actual encrypted password can act as salt.
     */
    salt = encrypted_passwd_to_check_against;
    given_passwd_encrypted = crypt(plain_txt_passwd, salt);

    passwd_match = !strcmp(encrypted_passwd_to_check_against,
                           given_passwd_encrypted);

    if (encrypted_passwd_to_check_against)
        free(encrypted_passwd_to_check_against);

    /*
     * DO NOT FREE THE STRING RETURNED FROM crypt(3).
     * Time wasted: ~5hrs
     *
     * Take note of the following golden words from the crypt(3) man page.
     *
     *  The return value points to static data whose content is
     *  overwritten by each call.
     *
     * free(given_passwd_encrypted);
     */

    return passwd_match;
}

/*
 * Return encrypted password for the given UID.
 * Return NULL if unsuccessful.
 */
static char *get_encrypted_user_passwd(uid_t uid)
{
    struct passwd *pwd = NULL;
    struct spwd *shadow_pwd = NULL;
    char *passwd = NULL;
    char *passwd_copy = NULL;

    /*
     * Get password field for the given UID.
     * Returned pointer should not be passed to free.
     */
    errno = 0;
    pwd = getpwuid(uid);
    if (!pwd) {
        log_fn("%s", strerror(errno));
        log_fn("Couldn't get password record for UID %d.", uid);
        return NULL;
    }

    passwd = pwd->pw_passwd;

    /*
     * If the password field is a lower-case “x”, then the encrypted password
     * is stored in the shadow(5) file instead.
     */
    if (!strcmp(passwd, "x")) {
        shadow_pwd = getspnam(pwd->pw_name);
        if (!shadow_pwd) {
            log_fn("%s", strerror(errno));
            log_fn("Couldn't get shadow file record for %s.", pwd->pw_name);
            return NULL;
        }

        passwd = shadow_pwd->sp_pwdp;
    }

    if (passwd) passwd_copy = strdup(passwd);

    return passwd_copy;
}

/*
 * Return the application password stored in PASSWD_FILE.
 *
 * If PASSWD_FILE is not present, return NULL.
 */
static char *get_sield_passwd(void)
{
    FILE *passwd_fp = NULL;
    char *encrypted_passwd = NULL;
    size_t len = 0;
    ssize_t read = 0;

    /* Check if password file exists. */
    if (access(PASSWD_FILE, F_OK) == -1) {
        log_fn("%s", strerror(errno));
        log_fn("Password file %s does not exist.", PASSWD_FILE);
        return NULL;
    }

    passwd_fp = fopen(PASSWD_FILE, "r");
    if (!passwd_fp) {
        log_fn("%s", strerror(errno));
        log_fn("Cannot open %s for reading.", PASSWD_FILE);
        return NULL;
    }

    read = getline(&encrypted_passwd, &len, passwd_fp);
    if (read == -1) {
        log_fn("%s", strerror(errno));
        log_fn("Unable to read %s.", PASSWD_FILE);
        return NULL;
    }

    fclose(passwd_fp);

    /* Remove newline. */
    encrypted_passwd[read-1] = '\0';

    return encrypted_passwd;
}
