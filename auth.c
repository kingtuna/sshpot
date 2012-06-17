#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAXBUF 100


/* Write interesting information about a connection attempt to  LOGFILE. */
static int log_attempt(char *time, char *ip, char *user, char *pass) {
    FILE *f;
    int r;

    if ((f = fopen(LOGFILE, "a+")) == NULL) {
        return -1;
    }

    if (DEBUG) { printf("%s %s %s %s\n", time, ip, user, pass); }
    r = fprintf(f, "%s %s %s %s\n", time, ip, user, pass);
    fclose(f);
    return r;
}


/* Stores the current UTC time in buf. */
static char *get_utc(char *buf) {
    time_t t;

    t = time(NULL);
    if (strftime(buf, MAXBUF, "%Y-%m-%d %H:%M:%S", gmtime(&t)) == 0) {
        buf = NULL;
    }

    return buf;
}


/* Stores the client's IP address in buf. */
static char *get_client_ip(ssh_session session, char *buf) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;

    getpeername(ssh_get_fd(session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, buf, len);

    return buf;
}


/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session) {
    ssh_message message;
    char c_addr[MAXBUF];
    char c_time[MAXBUF];

    /* Perform key exchange. */
    if (ssh_handle_key_exchange(session)) {
        fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(session));
        return -1;
    }
    if (DEBUG) { printf("Successful key exchange.\n"); }

    /* Wait for a message, which should be an authentication attempt. Send the default
     * reply if it isn't. Log the attempt and quit. */
    while (1) {
        if ((message = ssh_message_get(session)) == NULL) {
            break;
        }

        /* Log the authentication request and disconnect. */
        if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
            if (get_utc(c_time) != NULL) {
                log_attempt(c_time, get_client_ip(session, c_addr),
                    ssh_message_auth_user(message), ssh_message_auth_password(message));
            }
            else {
                fprintf(stderr, "Error getting time.\n");
            }
        }

        /* Send the default message regardless of the request type. */
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;
}
