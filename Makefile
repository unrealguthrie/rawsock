CC = gcc
EXE = rawsock
# CFLAGS = -W -Wall -Werror
CFLAGS = -Wall
DEPS = ./incl/bsc_ext.h ./incl/packet.h
OBJ = main.o ./incl/bsc_ext.o ./incl/packet.o

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

$(EXE): $(OBJ)
	gcc $(CFLAGS) -o $@ $^

