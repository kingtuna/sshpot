#include "config.h"

#include <libssh/server.h>

#include <stdio.h>

/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session) {
    ssh_message message;

    /* Perform key exchange. */
    if (ssh_handle_key_exchange(session)) {
        fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(session));
        return -1;
    }
    if (DEBUG) { printf("Successful key exchange.\n"); }

    /* Send the default reply until we get an auth attempt. Log the attempt and quit. */
    while (1) {
        if ((message = ssh_message_get(session)) == 0) { 
            break;
        }

        /* Log the authentication request and disconnect. */
        if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
            printf("%s %s\n", ssh_message_auth_user(message), ssh_message_auth_password(message));
        }

        /* Send the default message regardless of the request type. */
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;
}
