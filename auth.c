#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>


/* Stores the client's IP address in buf. */
static char *get_client_ip(ssh_session session, char *buf, unsigned int len) {
    struct sockaddr_storage addr;
    struct sockaddr_in *sock;
    int s;

    s = ssh_get_fd(session);
    getpeername(s, (struct sockaddr*)&addr, &len);

    sock = (struct sockaddr_in *)&addr;
    inet_ntop(AF_INET, &sock->sin_addr, buf, len);

    return buf;
}


/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session) {
    ssh_message message;
    char addr[INET_ADDRSTRLEN];

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
            get_client_ip(session, addr, sizeof addr);
            printf("%s %s %s\n", get_client_ip(session, addr, sizeof addr), 
                    ssh_message_auth_user(message), ssh_message_auth_password(message));
        }

        /* Send the default message regardless of the request type. */
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;
}
