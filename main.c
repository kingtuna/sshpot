#include "config.h"
#include "auth.h"

#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>

#define KEYS_FOLDER "./"


int main(int argc, char **argv) {
    ssh_session session;
    ssh_bind sshbind;

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
                exit(handle_auth(session));

            default:
                break;
        }
    }

    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}
