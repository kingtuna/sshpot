#include <libssh/server.h>

#include <stdio.h>

int handle_auth(ssh_session session) {
    ssh_message message;
    int auth_attempt = 0;

    /* Perform key exchange. */
    printf("Connection established, performing key exchange.\n");
    if (ssh_handle_key_exchange(session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return -1;
    }

    /* Send the default reply until we get an auth attempt. Log the attempt and quit. */
    while (!auth_attempt) {
        /* Get the message. */
        if ((message = ssh_message_get(session)) == 0) { 
            break;
        }

        /* Log the authentication request and disconnect. */
        if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
//          auth_attempt = 1;
            printf("%s %s\n", ssh_message_auth_user(message), ssh_message_auth_password(message));
        }

        /* Send the default message regardless of the request type. */
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    printf("Exiting child.\n");
    return 0;
}


