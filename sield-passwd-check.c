#define _GNU_SOURCE		/* getline(), strdup(), crypt() */
#define _BSD_SOURCE		/* strsep() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>		/* crypt() */

#include "sield-config.h"
#include "sield-log.h"
#include "sield-passwd-check.h"

static const char *shadow_file = "/etc/shadow";

static char *get_encrypted_user_passwd(const char *user);
int passwd_check(const char *plain_txt_passwd);

/*
 * Return encrypted password for given user from the shadow file.
 * Return NULL if unsuccessful.
 */
static char *get_encrypted_user_passwd(const char *user)
{
	if (! user) return NULL;
	FILE *shadow_fp = fopen(shadow_file, "r");
	if (! shadow_fp) {
		log_fn("Unable to open shadow file.");
		return NULL;
	}

	const char *colon = ":";
	char *encrypted_passwd_copy = NULL;
	char *line = NULL;
	size_t len = 0;

	/* Read shadow(5) */
	while (! encrypted_passwd_copy
			&& getline(&line, &len, shadow_fp) != -1) {

		char *line_copy = line;

		/* strsep modifies the first argument */
		char *user_t = strsep(&line_copy, colon);

		if (! strcmp(user_t, user)) {
			char *encrypted_passwd = strsep(&line_copy, colon);
			encrypted_passwd_copy = strdup(encrypted_passwd);
		}
	}

	if (! encrypted_passwd_copy)
		log_fn("Unable to find %s's encrypted password in shadow file.", user);

	/* Clean up */
	if (line) free(line);
	fclose(shadow_fp);

	return encrypted_passwd_copy;
}

/*
 * If SIELD password is defined explicitly, use that,
 * otherwise use root password.
 *
 * So check given password against either SIELD password
 * or the root password.
 *
 * Return 1 if password is correct, else return 0.
 */
int passwd_check(const char *plain_txt_passwd)
{
	char *encrypted_passwd_to_check_against =
		get_sield_attr("passwd");

	if (! encrypted_passwd_to_check_against) {
		log_fn("SIELD password not set. Using root password.");
		encrypted_passwd_to_check_against =
			get_encrypted_user_passwd("root");
	}

	if (! encrypted_passwd_to_check_against) return 0;

	/*
	 * salt is a character string starting with the characters "$id$"
	 * followed by a string terminated by "$":
	 *
	 * 	$id$salt$encrypted
	 *
	 * Here actual encrypted password can act as salt.
	 */
	char *salt = encrypted_passwd_to_check_against;
	char *given_passwd_encrypted = crypt(plain_txt_passwd, salt);

	int match = ! strcmp(encrypted_passwd_to_check_against,
				given_passwd_encrypted);

	free(encrypted_passwd_to_check_against);

	/*
	 * DO NOT FREE THE STRING RETURNED FROM crypt(3).
	 * Time wasted: ~5hrs
	 *
	 * Take note of the following golden words from the crypt(3) man page.
	 *
	 * 	The return value points to static data whose content is
	 * 	overwritten by each call.
	 *
	 * free(given_passwd_encrypted);
	 */

	return match;
}
