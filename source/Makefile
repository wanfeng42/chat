CC = gcc
PROGS = serv
CFLAGS = -Wall -g
LIBS = -levent -levent_pthreads
all: ${PROGS}
serv:chat_serv.o protocol_process.o serv.h
	${CC} ${CFLAGS}   -o $@ $^  ${INCLUDE}  ${LIBS}

chat_serv.o:serv.h

protocol_process.o:serv.h

test:testcli.o
clean:
	rm -f serv test chat_serv.o protocol_process.o testcli.o
