#define _GNU_SOURCE		/* getline(), strdup(), crypt() */
#define _BSD_SOURCE		/* strsep() */
#include <errno.h>
#include <pwd.h>
#include <shadow.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>		/* crypt() */

#include "sield-config.h"
#include "sield-log.h"
#include "sield-passwd-check.h"


static char *get_encrypted_user_passwd(uid_t uid);
int passwd_check(const char *plain_txt_passwd);

/*
 * Return encrypted password for the given UID.
 * Return NULL if unsuccessful.
 */
static char *get_encrypted_user_passwd(uid_t uid)
{
	/*
	 * Get passwd field for the superuser account
	 *
	 * Returned pointer should not be passed to free.
	 */
	errno = 0;
	struct passwd *pwd = getpwuid(uid);
	if (! pwd) {
		log_fn("%s", strerror(errno));
		log_fn("Couldn't get password record for UID %d.", uid);
		return NULL;
	}

	char *passwd = pwd->pw_passwd;

	/*
	 * If the password field is a lower-case “x”, then
	 * the encrypted password is actually stored in 
	 * the shadow(5) file instead.
	 */
	if (! strcmp(pwd->pw_passwd, "x")) {
		struct spwd *shadow_pwd = getspnam(pwd->pw_name);
		if (! shadow_pwd) {
			log_fn("%s\n", strerror(errno));
			log_fn("Couldn't get shadow file record for %s\n",
				pwd->pw_name);
			return NULL;
		}

		passwd = shadow_pwd->sp_pwdp;
	}

	char *passwd_copy = NULL;
	if (passwd) passwd_copy = strdup(passwd);

	return passwd_copy;
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
		log_fn("SIELD password not set. Using superuser password.");
		encrypted_passwd_to_check_against =
			get_encrypted_user_passwd(0);
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
