#include "config.h"
#include "auth.h"

#include <libssh/libssh.h>
#include <libssh/server.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <errno.h>
#include <sys/wait.h>

#define MINPORT 0
#define MAXPORT 65535

/* Global so they can be cleaned up at SIGINT. */
static ssh_session session;
static ssh_bind sshbind;


/* Print usage information to `stream', exit with `exit_code'. */
static void usage(FILE *stream, int exit_code) {
    fprintf(stream, "Usage: sshpot [-h] [-p <port>]\n");
    fprintf(stream,
            "   -h  --help          Display this usage information.\n"
            "   -p  --port <port>   Port to listen on; defaults to 22.\n");
    exit(exit_code);
}


/* Return the c-string `p' as an int if it is a valid port 
 * in the range of MINPORT - MAXPORT, or -1 if invalid. */
static int valid_port(char *p) {
    int port;
    char *endptr;

    port = strtol(p, &endptr, 10);
    if (port >= MINPORT && port <= MAXPORT && !*endptr && errno == 0) 
        return port;

    return -1;
}


/* Signal handler for cleaning up after children. We want to do cleanup
 * at SIGCHILD instead of waiting in main so we can accept multiple
 * simultaneous connections. */
static int cleanup(void) {
    int status;
    int pid;
    pid_t wait3(int *statusp, int options, struct rusage *rusage);

    while ((pid=wait3(&status, WNOHANG, NULL)) > 0) {
        if (DEBUG) { printf("process %d reaped\n", pid); }
    }

    /* Re-install myself for the next child. */
    signal(SIGCHLD, (void (*)())cleanup);

    return 0;
}


/* SIGINT handler. Cleanup the ssh* objects and exit. */
static void wrapup(void) {
    ssh_disconnect(session);
    ssh_bind_free(sshbind);
    ssh_finalize();
    exit(0);
}


int main(int argc, char *argv[]) {
    int port = DEFAULTPORT;

    /* Handle command line options. */
    int next_opt = 0;
    const char *short_opts = "hp:";
    const struct option long_opts[] = {
        { "help",   0, NULL, 'h' },
        { "port",   1, NULL, 'p' },
        { NULL,     0, NULL, 0   }
    };

    while (next_opt != -1) {
        next_opt = getopt_long(argc, argv, short_opts, long_opts, NULL);
        switch (next_opt) {
            case 'h':
                usage(stdout, 0);
                break;

            case 'p':
                if ((port = valid_port(optarg)) < 0) {
                    fprintf(stderr, "Port must range from %d - %d\n\n", MINPORT, MAXPORT);
                    usage(stderr, 1);
                }
                break;

            case '?':
                usage(stderr, 1);
                break;

            case -1:
                break;

            default:
                fprintf(stderr, "Fatal error, aborting...\n");
                exit(1);
        }
    }

    /* There shouldn't be any other parameters. */
    if (argv[optind]) {
        fprintf(stderr, "Invalid parameter `%s'\n\n", argv[optind]);
        usage(stderr, 1);
    }

    /* Install the signal handlers to cleanup after children and at exit. */
    signal(SIGCHLD, (void (*)())cleanup);
    signal(SIGINT, (void(*)())wrapup);

    /* Create and configure the ssh session. */
    session=ssh_new();
    sshbind=ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, LISTENADDRESS);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "ssh-rsa");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,RSA_KEYFILE);

    /* Listen on `port' for connections. */
    if (ssh_bind_listen(sshbind) < 0) {
        printf("Error listening to socket: %s\n",ssh_get_error(sshbind));
        return -1;
    }
    if (DEBUG) { printf("Listening on port %d.\n", port); }

    /* Loop forever, waiting for and handling connection attempts. */
    while (1) {
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: `%s'.\n",ssh_get_error(sshbind));
            return -1;
        }
        if (DEBUG) { printf("Accepted a connection.\n"); }

        switch (fork())  {
            case -1:
                fprintf(stderr,"Fork returned error: `%d'.\n",-1);
                exit(-1);

            case 0:
                exit(handle_auth(session));

            default:
                break;
        }
    }

    return 0;
}
