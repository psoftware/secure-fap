all: client server



client: client.o commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o
	g++ client.o commonlib/commonlib.o commonlib/net_wrapper.o commonlib/messages.o -o client -lcrypto -g

server: server.o commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o
	g++ server.o commonlib/commonlib.o commonlib/net_wrapper.o commonlib/messages.o -o server -lcrypto -g

client.o: client.c
	g++ -c -g -Wall client.c -o client.o

server.o: server.c
	g++ -c -g -Wall server.c -o server.o


commonlib/commonlib.o: commonlib/commonlib.c commonlib/commonlib.h
	g++ -c -g commonlib/commonlib.c -o commonlib/commonlib.o

commonlib/net_wrapper.o: commonlib/net_wrapper.c commonlib/net_wrapper.h
	g++ -c commonlib/net_wrapper.c -o commonlib/net_wrapper.o

commonlib/messages.o: commonlib/messages.c commonlib/messages.h
	g++ -c commonlib/messages.c -o commonlib/messages.o

clean:
	rm -f client server *.o commonlib/*.o
