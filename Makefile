all: client server

client: client.o net_wrapper.o commonlib_obj
	gcc client.o commonlib/commonlib.o net_wrapper.o -o client -lcrypto -g

server: server.o net_wrapper.o commonlib_obj
	gcc server.o commonlib/commonlib.o net_wrapper.o -o server -lcrypto -g

client.o: client.c
	gcc -c -g client.c -o client.o

server.o: server.c
	gcc -c -g server.c -o server.o


commonlib_obj: commonlib/commonlib.c commonlib/commonlib.h
	gcc -c -g commonlib/commonlib.c -o commonlib/commonlib.o

net_wrapper.o: net_wrapper.c net_wrapper.h
	gcc -c net_wrapper.c -o net_wrapper.o


clean:
	rm -f client server *.o commonlib/commonlib.o
