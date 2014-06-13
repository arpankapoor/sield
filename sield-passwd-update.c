#define _GNU_SOURCE		/* getline(), crypt() */
#include <stdio.h>
#include <stdlib.h>		/* rand(), srand(), free() */
#include <string.h>		/* strcmp() */
#include <termios.h>		/* tcgetattr(), tcsetattr() */
#include <time.h>		/* time() */
#include <unistd.h>		/* crypt() */

#include "sield-config.h"	/* set-sield-attr() */
#include "sield-log.h"		/* log_fn() */
#include "sield-passwd.h"	/* passwd_check() */

static ssize_t get_passwd(char **plain_txt_passwd, size_t *n, FILE *stream);
static char *generate_salt(void);
static int set_passwd(const char *plain_txt_passwd);

/*
 * Switch off terminal echoing and retrieve password.
 *
 * Return number of characters read (excluding newline)
 * 	OR
 * -1 on error.
 */
static ssize_t get_passwd(char **plain_txt_passwd, size_t *n, FILE *stream)
{
	struct termios old, new;

	/* Get old terminal attributes. */
	if (tcgetattr(fileno(stream), &old) == -1) {
		fprintf(stderr,"Unable to GET terminal attributes.");
		log_fn("Unable to GET terminal attributes.");
		return -1;
	}

	new = old;
	new.c_lflag &= ~ECHO;	/* Turn echoing off. */

	if (tcsetattr(fileno(stream), TCSAFLUSH, &new) == -1) {
		fprintf(stderr, "Unable to SET terminal attributes.");
		log_fn ("Unable to SET terminal attributes.");
		return -1;
	}

	/* Read password */
	ssize_t read;
	read = getline(plain_txt_passwd, n, stream);

	/* Restore terminal settings. */
	(void) tcsetattr(fileno(stream), TCSAFLUSH, &old);

	/* Change newline to '\0'. */
	if (read > 0) {
		char *passwd = *plain_txt_passwd;
		passwd[read - 1] = '\0';
	}

	return read - 1;
}

/*
 * Generate salt for SHA-512 for crypt(1).
 */
static char *generate_salt(void)
{
	char *salt = calloc(21, sizeof(char));
	/* salt = "$6$random_string$" */
	int idx = 0;
	salt[idx++] = '$';
	salt[idx++] = '6';
	salt[idx++] = '$';

	/* As defined in crypt(3). */
	static const char set[] =
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"0123456789"
		"./";

	int i, size = strlen(set);
	srand(time(NULL));
	for (i = 0; i < 16; i++)
		salt[idx++] = set[rand() / (RAND_MAX / size + 1)];
	salt[idx] = '$';
	salt[idx] = '\0';
	return salt;
}

/*
 * Update password.
 *
 * Encrypt using SHA-512 with a 16 byte salt.
 */
static int set_passwd(const char *plain_txt_passwd)
{
	/* Generate a salt. */
	char *salt = generate_salt();
	char *encrypted_passwd = crypt(plain_txt_passwd, salt);

	int rc = set_sield_attr("passwd", encrypted_passwd);

	free(salt);
	/*
	 * DON'T FREE RETURN VALUE OF crypt(3).
	 *
	 * free(encrypted_passwd);
	 */

	return rc;
}

int main(int argc, char **argv)
{
	printf("Changing password for SIELD\n");
	printf("(current) password: ");

	char *curr_plain_txt_passwd = NULL;
	char *new_plain_txt_passwd_1 = NULL, *new_plain_txt_passwd_2 = NULL;
	size_t passwd_len = 0;

	/* Get current password */
	if (get_passwd(&curr_plain_txt_passwd, &passwd_len, stdin) == -1)
		goto error_cleanup;

	/* Check given password. */
	if (! passwd_check(curr_plain_txt_passwd)) {
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
	if (strcmp(new_plain_txt_passwd_1, new_plain_txt_passwd_2)) {
		printf("\nGiven passwords do not match.\n");
		printf("Password unchanged.\n");
		goto error_cleanup;
	}

	/* Check if new password is the same as the old one. */
	if (! strcmp(new_plain_txt_passwd_1, curr_plain_txt_passwd)) {
		printf("\nPassword unchanged.\n");
	} else {
		if (set_passwd(new_plain_txt_passwd_1)) {
			printf("\nPassword updated successfully.\n");
			log_fn("Password updated.\n");
		} else {
			fprintf(stderr, "\nFailed to change password.\n");
		}
	}

	free(curr_plain_txt_passwd);
	free(new_plain_txt_passwd_1);
	free(new_plain_txt_passwd_2);

	exit(EXIT_SUCCESS);

error_cleanup:
	if (curr_plain_txt_passwd) free(curr_plain_txt_passwd);
	if (new_plain_txt_passwd_1) free(new_plain_txt_passwd_1);
	if (new_plain_txt_passwd_2) free(new_plain_txt_passwd_2);
	exit(EXIT_FAILURE);
}
