CC = gcc
CFLAGS = -g -Wall

all: sshpot

sshpot: main.o auth.o
	$(CC) $(CFLAGS) $^ -lssh -o $@

main.o: main.c config.h
	$(CC) $(CFLAGS) -c main.c

auth.o: auth.c auth.h
	$(CC) $(CFLAGS) -c auth.c

clean:
	\/bin/rm -f *.o
