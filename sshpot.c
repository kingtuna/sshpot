#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>

#define KEYS_FOLDER "./"


int main(int argc, char **argv) {
    ssh_session session;
    ssh_bind sshbind;
    ssh_message message;
    int auth_attempt = 0;

    sshbind=ssh_bind_new();
    session=ssh_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "sshpot.dsa.key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "sshpot.rsa.key");

    /* Listen on PORT for connections. */
    printf("Listening on %s.\n", PORT);
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }

    //Loop here.
    while (1) {
    
        /* Wait for a connection. */
        printf("Accepted a connection.\n");
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
        printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
        return 1;
        }

        //Fork here.
        switch (fork())  {
            case -1:
                fprintf(stderr,"fork returned error #%d\n",-1);
                exit(-1);

            case 0:
                /* Perform key exchange. */
                printf("Connection established, performing key exchange.\n");
                if (ssh_handle_key_exchange(session)) {
                    printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
                    return 1;
                }

                /* Send the default reply until we get an auth attempt. Log the attempt and quit. */
                while (!auth_attempt) {
                    /* Get the message. */
                    if ((message = ssh_message_get(session)) == 0) { 
                        break;
                    }

                    /* Log the authentication request and disconnect. */
                    if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
//                        auth_attempt = 1;
                        printf("%s %s\n", ssh_message_auth_user(message), ssh_message_auth_password(message));
                    }

                    /* Send the default message regardless of the request type. */
                    ssh_message_reply_default(message);

                    ssh_message_free(message);
                }

                printf("Exiting child.\n");
                exit(0);

            default:
                break;
        }
    }

    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}
