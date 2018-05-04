all: client server



client: client.o commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o
	g++ client.o commonlib/commonlib.o commonlib/net_wrapper.o commonlib/messages.o -o client -lcrypto -g

server: server.o commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o
	g++ server.o commonlib/commonlib.o commonlib/net_wrapper.o commonlib/messages.o -o server -lcrypto -g

client.o: client.cpp
	g++ -c -g -Wall client.cpp -o client.o

server.o: server.cpp
	g++ -c -g -Wall server.cpp -o server.o


commonlib/commonlib.o: commonlib/commonlib.cpp commonlib/commonlib.h
	g++ -c -g commonlib/commonlib.cpp -o commonlib/commonlib.o

commonlib/net_wrapper.o: commonlib/net_wrapper.c commonlib/net_wrapper.h
	gcc -c commonlib/net_wrapper.c -o commonlib/net_wrapper.o

commonlib/messages.o: commonlib/messages.c commonlib/messages.h
	gcc -c commonlib/messages.c -o commonlib/messages.o

clean:
	rm -f client server *.o commonlib/*.o
