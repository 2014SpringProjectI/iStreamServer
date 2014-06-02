CC=gcc
CFLAGS=-I.
DEPS=lib/structdef.h
OBJ= iStreamServer.o lib/utils.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

iStreamServer: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean: 
	rm -f iStreamServer $(OBJ)
