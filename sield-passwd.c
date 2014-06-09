#define _GNU_SOURCE		/* getline(), strdup() */
#define _BSD_SOURCE		/* strsep() */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *shadow_file = "/etc/shadow";

/*
 * Return encrypted password for given user from the shadow file.
 * Return NULL if unsuccessful.
 */
static char *get_encrypted_user_passwd(const char *user)
{
	FILE *shadow_fp = fopen(shadow_file, "r");
	if (! shadow_fp) {
		log_fn("Unable to open shadow file.");
		return NULL;
	}

	const char colon = ":";
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

		free(line);
		line = NULL;
		len = 0;
	}

	if (! encrypted_password_copy)
		log_fn("Unable to find %s's encrypted password in shadow file.", user);

	fclose(shadow_fp);
	return encrypted_passwd_copy;
}
