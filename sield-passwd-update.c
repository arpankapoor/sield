#define _GNU_SOURCE     /* crypt() */
#include <errno.h>      /* errno */
#include <stdio.h>      /* fopen() */
#include <stdlib.h>     /* rand(), srand(), free() */
#include <string.h>     /* strcmp() */
#include <sys/stat.h>   /* mkdir() */
#include <sys/types.h>  /* mkdir() */
#include <time.h>       /* time() */
#include <unistd.h>     /* crypt() */

#include "sield-log.h"          /* log_fn() */
#include "sield-passwd-check.h" /* is_passwd_correct() */
#include "sield-passwd-cli-get.h"   /* get_passwd() */

static char *generate_salt(void);
static int set_passwd(const char *plain_txt_passwd);

/*
 * Generate salt for SHA-512 for crypt(1).
 */
static char *generate_salt(void)
{
    /* As defined in crypt(3). */
    const char set[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "./";
    const int SALT_LEN = 16;

    char *salt = NULL;
    int idx = 0;
    int i, size;

    salt = calloc(SALT_LEN + 5, sizeof(char));
    if (salt == NULL) {
        log_fn("calloc(): Memory error.");
        return NULL;
    }

    /* salt = "$6$random_string$" */
    salt[idx++] = '$';
    salt[idx++] = '6';
    salt[idx++] = '$';

    size = strlen(set);

    srand(time(NULL));

    for (i = 0; i < SALT_LEN; i++)
        salt[idx++] = set[rand() / (RAND_MAX / size + 1)];

    salt[idx++] = '$';
    salt[idx] = '\0';

    return salt;
}

/*
 * Update password.
 *
 * Encrypt using SHA-512 with a 16 byte salt.
 *
 * Return 0 on success, else return -1.
 */
static int set_passwd(const char *plain_txt_passwd)
{
    const char *CONF_DIR = "/etc/sield/";
    char *salt = NULL;
    char *encrypted_passwd = NULL;
    FILE *passwd_fp = NULL;

    /* Generate a salt. */
    salt = generate_salt();
    if (salt == NULL) return -1;

    encrypted_passwd = crypt(plain_txt_passwd, salt);
    if (encrypted_passwd == NULL) {
        log_fn("Error encrypting password");
        free(salt);
        return -1;
    }

    /* Make the app directory if not already present */
    if (mkdir(CONF_DIR, S_IRWXU) == -1 && errno != EEXIST) {
        log_fn("mkdir(): %s: %s", CONF_DIR, strerror(errno));
        free(salt);
        return -1;
    }

    passwd_fp = fopen(PASSWD_FILE, "w");
    if (passwd_fp == NULL) {
        log_fn("fopen(): %s: %s", PASSWD_FILE, strerror(errno));
        free(salt);
        return -1;
    }

    fprintf(passwd_fp, "%s\n", encrypted_passwd);

    free(salt);
    fclose(passwd_fp);
    /*
     * DON'T FREE RETURN VALUE OF crypt(3).
     *
     * free(encrypted_passwd);
     */

    /* Change owner of password file to superuser. */
    if (chown(PASSWD_FILE, 0, 0) == -1) {
        log_fn("Unable to change owner of password file \"%s\" to superuser.",
               PASSWD_FILE);
        return -1;
    }

    /* Set its permission bits to read-write only by owner. */
    if (chmod(PASSWD_FILE, S_IRUSR | S_IWUSR) == -1) {
        log_fn("Unable to change password file \"%s\" permission bits. %s",
               PASSWD_FILE, strerror(errno));
        remove(PASSWD_FILE);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    char *curr_plain_txt_passwd = NULL;
    char *new_plain_txt_passwd_1 = NULL;
    char *new_plain_txt_passwd_2 = NULL;
    size_t passwd_len = 0;

    printf("Changing password for SIELD\n");
    printf("(current) password: ");

    /* Get current password */
    if (get_passwd(&curr_plain_txt_passwd, &passwd_len, stdin) == -1)
        goto error_cleanup;

    /* Check given password. */
    if (!is_passwd_correct(curr_plain_txt_passwd)) {
        printf("\nAuthentication failure.\n");
        printf("Password unchanged.\n");
        goto error_cleanup;
    }

    /* Fetch new password. */
    printf("\nEnter new password: ");
    if (get_passwd(&new_plain_txt_passwd_1, &passwd_len, stdin) == -1)
        goto error_cleanup;

    /* Retype new password. */
    printf("\nRetype new password: ");
    if (get_passwd(&new_plain_txt_passwd_2, &passwd_len, stdin) == -1)
        goto error_cleanup;

    /* Check if the 2 passwords match. */
    if (strcmp(new_plain_txt_passwd_1, new_plain_txt_passwd_2) != 0) {
        printf("\nGiven passwords do not match.\n");
        printf("Password unchanged.\n");
        goto error_cleanup;
    }

    /* Check if new password is the same as the old one. */
    if (strcmp(new_plain_txt_passwd_1, curr_plain_txt_passwd) == 0) {
        printf("\nPassword unchanged.\n");
    } else if (set_passwd(new_plain_txt_passwd_1) == 0) {
        printf("\nPassword updated successfully.\n");
        log_fn("Password updated.");
    } else {
        fprintf(stderr, "\nFailed to change password.\n");
    }

    if (curr_plain_txt_passwd) free(curr_plain_txt_passwd);
    if (new_plain_txt_passwd_1) free(new_plain_txt_passwd_1);
    if (new_plain_txt_passwd_2) free(new_plain_txt_passwd_2);

    exit(EXIT_SUCCESS);

error_cleanup:
    log_fn("Failed password change event.");
    if (curr_plain_txt_passwd) free(curr_plain_txt_passwd);
    if (new_plain_txt_passwd_1) free(new_plain_txt_passwd_1);
    if (new_plain_txt_passwd_2) free(new_plain_txt_passwd_2);
    exit(EXIT_FAILURE);
}
