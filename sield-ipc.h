#ifndef _SIELD_IPC_H_
#define _SIELD_IPC_H_

static const char *PROGRAM_NAME = "sld";
static const char *FIFO_DIR = "/tmp/sld/";

/* Structure to send through string length information to the daemon. */
struct auth_len {
    int user_len;   /* username length */
    int tty_len;    /* ttyname length */
    int pwd_len;    /* password length */
};

#endif
