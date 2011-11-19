#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/wait.h>

#define KEYS_FOLDER "./"

/* Log the password attempt and fail. */
static int auth_password(char *user, char *password){
    printf("%s %s\n", user, password);
    return 0;
}

static int request_handler(ssh_message message) {
    char *username = ssh_message_auth_user(message);
    char *password = ssh_message_auth_password(message);

    switch (ssh_message_type(message)) {
        case SSH_REQUEST_AUTH:
            if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                if (auth_password(username, password)) {
                    break;
                }
            } 
            /* not authenticated, send default message. */
            else {
                ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(message);
                break;
            }
        default:
            ssh_message_reply_default(message);
    }

    ssh_message_free(message);
    return 0;
}


static int reaper(void) {
    int status;
    int pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);
  
    while ((pid=wait3(&status, WNOHANG, NULL)) > 0) {
        printf("process %d reaped\n", pid);
    }
  
    /* Re-install myself for the next child. */
    signal(SIGCHLD, (void (*)())reaper);

    return(0);
}


int main(int argc, char **argv) {
    ssh_session session;
    ssh_bind sshbind;
    ssh_message message;
    int r;
    int auth = 0;

    sshbind=ssh_bind_new();
    session=ssh_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "sshpot.dsa.key");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "sshpot.rsa.key");

    /* Listen on PORT for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return 1;
    }
    
    r=ssh_bind_accept(sshbind, session);
    if (r==SSH_ERROR) {
      printf("error accepting a connection : %s\n",ssh_get_error(sshbind));
      return 1;
    }

    if (ssh_handle_key_exchange(session)) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(session));
        return 1;
    }

    signal(SIGCHLD, (void (*)())reaper);

    /* Loop forever, waiting for connections. */
//    while (1) {
//        /* Accept a connection */
//            message = ssh_message_get(session);
//            if (!message) {
//                continue;
//            }
//
//        /* Fork off a slave to handle the request */
//        switch (fork())  {
//            case -1:        /* error */
//                fprintf(stderr,"fork returned error #%d\n",-1);
//                exit(-1);
//
//            case 0:         /* child */
//                exit(request_handler(message));
//
//            default:        /* parent */
//                break;
//        }
//    }

    /* Got a connection, try to auth. */
    do {
        message=ssh_message_get(session);
        if(!message)
            break;
        switch(ssh_message_type(message)){
            case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(message)){
                    case SSH_AUTH_METHOD_PASSWORD: 
                        if(auth_password(ssh_message_auth_user(message), ssh_message_auth_password(message))){
                            /* This should never succeed, but if it does pretend the password was bad. */
                            ssh_message_reply_default(message);
                            break;
                        }
                        // not authenticated, send default message
                    case SSH_AUTH_METHOD_NONE:
                    default:
                        ssh_message_auth_set_methods(message,SSH_AUTH_METHOD_PASSWORD);
                        ssh_message_reply_default(message);
                        break;
                }
                break;
            default:
                ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (!auth);

    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();

    return 0;
}
