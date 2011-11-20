#include "config.h"
#include "auth.h"

#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#define KEYS_FOLDER "./"

/* Keep track of the number of concurrent connections. */
static int total_connections = 0;

static int cleanup(void) {
    int status;
    int pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);

    while ((pid=wait3(&status, WNOHANG, NULL)) > 0) {
        if (DEBUG) { printf("process %d reaped\n", pid); }
        total_connections--;
        printf("*** Decrementing total_connections: %d ***\n", total_connections);
    }

    /* Re-install myself for the next child */
    signal(SIGCHLD, (void (*)())cleanup);

    return 0;
}


int main(int argc, char **argv) {
    ssh_session session;
    ssh_bind sshbind;
    int child_ret = 0;

    /* Install the handler to cleanup after children. */
    signal(SIGCHLD, (void (*)())cleanup);

    session=ssh_new();
    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "sshpot.dsa.key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "sshpot.rsa.key");

    /* Listen on PORT for connections. */
    if (DEBUG) { printf("Listening on %s.\n", PORT); }
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }

    //Loop here.
    while (1) {
        /* Wait for a connection. */
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            printf("Error accepting a connection: %s\n",ssh_get_error(sshbind));
            return -1;
        }
        if (DEBUG) { printf("Accepted a connection.\n"); }
        total_connections++;

        //Fork here.
        switch (fork())  {
            case -1:
                fprintf(stderr,"fork returned error #%d\n",-1);
                exit(-1);

            case 0:
                printf("*** Total connections = %d ***\n", total_connections);
                if (total_connections > MAXCONNECTIONS) {
                    printf("Too many connections!\n");
                    /* This causes the client to hang. */
                    ssh_disconnect(session);
                }
                else {
                    child_ret = handle_auth(session);
                }
                exit(child_ret);

            default:
                break;
        }
    }

    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}
