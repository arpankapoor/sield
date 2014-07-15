#include <stdlib.h>     /* NULL */
#include <utmp.h>

#include "sield-passwd-ask.h"
#include "sield-passwd-gui.h"
#include "sield-passwd-cli.h"

static int runlevel(void);

/* Prompt for password according to the runlevel. */
int
ask_passwd(const char *manufacturer, const char *product, const char *devnode)
{
    int rl = runlevel();

    if (rl == 5) return ask_passwd_gui(manufacturer, product);
    if (rl == 3) return ask_passwd_cli(manufacturer, product, devnode);
    return 0;
}

/* Return runlevel of the system. */
static int runlevel(void)
{
    struct utmp *ut = NULL;
    int rl = 0;

    setutent();
    while ((ut = getutent()) != NULL) {
        if (ut->ut_type == RUN_LVL) {
            rl = (ut->ut_pid % 256) - '0';
            break;
        }
    }

    endutent();
    return rl;
}
