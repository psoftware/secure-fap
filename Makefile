all: client server

commonlib_obj: commonlib/commonlib.c commonlib/commonlib.h
	gcc -c -g commonlib/commonlib.c -o commonlib/commonlib.o

client_obj: client.c
	gcc -c -g client.c -o client.o

server_obj: server.c
	gcc -c -g server.c -o server.o

client: client_obj commonlib_obj
	gcc client.o commonlib/commonlib.o -o client -lcrypto

server: server_obj commonlib_obj
	gcc server.o commonlib/commonlib.o -o server -lcrypto

clean:
	rm -f client server *.o commonlib/commonlib.o
