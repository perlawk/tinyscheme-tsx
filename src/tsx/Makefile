DEBUG=
SCHEME_H_DIR=../
CC=gcc
CFLAGS=-DUSE_DL=1 -I $(SCHEME_H_DIR) -fPIC
LIB = -L../ -L /usr/lib

tsx.so : tsx.o ecc.o
	$(CC) -shared $(LIB) -o $@ $(DEBUG) $^ -lsqlite3

ecc.o:ecc.c 
	$(CC) -c $(CFLAGS) $^

tsx.o:tsx.c
	$(CC) -c $(CFLAGS) $^

.PHONY : clean
clean:
	rm -f *.o
	rm -f tsx.so
	rm -f *~
