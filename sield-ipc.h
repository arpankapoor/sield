#ifndef _SIELD_IPC_H_
#define _SIELD_IPC_H_

/* Structure to send through string length information to the daemon. */
struct auth_len {
    int user_len;   /* username length */
    int tty_len;    /* ttyname length */
    int pwd_len;    /* password length */
};

#endif
