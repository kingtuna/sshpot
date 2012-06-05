Name:

    sshpot


Description: 

    An ssh server that never authenticates. Instead, it logs the username,
    password, IP address and time of every login attempt.


Installation:

    1. Generate an RSA public key for use by the server:
        > ssh-keygen -t rsa 

    2. Edit config.h to set the desired options. In particular, you must set
       RSA_KEYFILE to the path to the public key generated in step one. LOGFILE 
       must be set to a location where the user running sshpot can write.

    3. Compile the software:
        > make
        # make install (optional, but necessary to listen on ports < 1024.)


Usage:

    sshpot [-h] [-p <port>]
        -h  --help          Display this usage information.
        -p  --port <port>   Port to listen on; defaults to 22.


Dependencies:

    libssh http://www.libssh.org/
