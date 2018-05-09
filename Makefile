COMMONLIB_OBJ = commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o commonlib/SymmetricCipher.o commonlib/EncryptSession.o commonlib/DecryptSession.o commonlib/SignatureVerifier.o commonlib/SignatureMaker.o commonlib/DynamicArray.o

all: client server

client: client.o $(COMMONLIB_OBJ)
	g++ client.o $(COMMONLIB_OBJ) -o client -lcrypto -g

server: server.o $(COMMONLIB_OBJ)
	g++ server.o $(COMMONLIB_OBJ) -o server -lcrypto -g

client.o: client.cpp
	g++ -c -g -Wall client.cpp -o client.o

server.o: server.cpp
	g++ -c -g -Wall server.cpp -o server.o

test.o: test.cpp
	g++ -c -g -Wall test.cpp -o test.o

commonlib/commonlib.o: commonlib/commonlib.cpp commonlib/commonlib.h
	g++ -c -g commonlib/commonlib.cpp -o commonlib/commonlib.o

commonlib/net_wrapper.o: commonlib/net_wrapper.c commonlib/net_wrapper.h
	gcc -c commonlib/net_wrapper.c -o commonlib/net_wrapper.o

commonlib/messages.o: commonlib/messages.c commonlib/messages.h
	gcc -c commonlib/messages.c -o commonlib/messages.o

commonlib/EncryptSession.o: commonlib/EncryptSession.cpp commonlib/EncryptSession.h
	g++ -c commonlib/EncryptSession.cpp -o commonlib/EncryptSession.o

commonlib/DecryptSession.o: commonlib/DecryptSession.cpp commonlib/DecryptSession.h
	g++ -c commonlib/DecryptSession.cpp -o commonlib/DecryptSession.o

commonlib/SymmetricCipher.o: commonlib/SymmetricCipher.cpp commonlib/SymmetricCipher.h
	g++ -c commonlib/SymmetricCipher.cpp -o commonlib/SymmetricCipher.o

commonlib/SignatureVerifier.o: commonlib/SignatureVerifier.cpp commonlib/SignatureVerifier.h
	g++ -c commonlib/SignatureVerifier.cpp -o commonlib/SignatureVerifier.o

commonlib/SignatureMaker.o: commonlib/SignatureMaker.cpp commonlib/SignatureMaker.h
	g++ -c commonlib/SignatureMaker.cpp -o commonlib/SignatureMaker.o

commonlib/DynamicArray.o: commonlib/DynamicArray.cpp commonlib/DynamicArray.h
	g++ -c commonlib/DynamicArray.cpp -o commonlib/DynamicArray.o

clean:
	rm -f client server *.o commonlib/*.o
