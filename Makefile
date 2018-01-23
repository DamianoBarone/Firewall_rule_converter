all: test
clean:
	rm *o test

control.o: packet.h control.c
	cc -c -O2 -Wall -Werror control.c

test: test.c control.o
	cc -o test test.c control.o -O2 -Wall -Werror
