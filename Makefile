all: client server



client: client.o commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o
	gcc client.o commonlib/commonlib.o commonlib/net_wrapper.o commonlib/messages.o -o client -lcrypto -g

server: server.o commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o
	gcc server.o commonlib/commonlib.o commonlib/net_wrapper.o commonlib/messages.o -o server -lcrypto -g

client.o: client.c
	gcc -c -g -Wall client.c -o client.o

server.o: server.c
	gcc -c -g -Wall server.c -o server.o


commonlib/commonlib.o: commonlib/commonlib.c commonlib/commonlib.h
	gcc -c -g commonlib/commonlib.c -o commonlib/commonlib.o

commonlib/net_wrapper.o: commonlib/net_wrapper.c commonlib/net_wrapper.h
	gcc -c commonlib/net_wrapper.c -o commonlib/net_wrapper.o

commonlib/messages.o: commonlib/messages.c commonlib/messages.h
	gcc -c commonlib/messages.c -o commonlib/messages.o

clean:
	rm -f client server *.o commonlib/*.o
