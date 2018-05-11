COMMONLIB_OBJ = commonlib/net_wrapper.o commonlib/messages.o commonlib/commonlib.o commonlib/SymmetricCipher.o commonlib/EncryptSession.o commonlib/DecryptSession.o commonlib/SignatureVerifier.o commonlib/SignatureMaker.o commonlib/DynamicArray.o
COMMON_FLAGS = -std=c++14 -g -pthread

all: client server database.sqlite3

database.sqlite3: script.sql
	sqlite3 database.sqlite3 < script.sql

client: client.o $(COMMONLIB_OBJ)
	g++ $(COMMON_FLAGS) client.o $(COMMONLIB_OBJ) -o client -lcrypto

server: server.o $(COMMONLIB_OBJ)
	g++ $(COMMON_FLAGS) server.o $(COMMONLIB_OBJ) -o server -lcrypto -lsqlite3

client.o: client.cpp
	g++ $(COMMON_FLAGS) -c -Wall client.cpp -o client.o

server.o: server.cpp
	g++ $(COMMON_FLAGS) -c -Wall server.cpp -o server.o

commonlib/commonlib.o: commonlib/commonlib.cpp commonlib/commonlib.h
	g++ $(COMMON_FLAGS) -c commonlib/commonlib.cpp -o commonlib/commonlib.o

commonlib/net_wrapper.o: commonlib/net_wrapper.c commonlib/net_wrapper.h
	gcc -c -g commonlib/net_wrapper.c -o commonlib/net_wrapper.o

commonlib/messages.o: commonlib/messages.c commonlib/messages.h
	gcc -c -g commonlib/messages.c -o commonlib/messages.o

commonlib/EncryptSession.o: commonlib/EncryptSession.cpp commonlib/EncryptSession.h
	g++ -c -g commonlib/EncryptSession.cpp -o commonlib/EncryptSession.o

commonlib/DecryptSession.o: commonlib/DecryptSession.cpp commonlib/DecryptSession.h
	g++ -c -g commonlib/DecryptSession.cpp -o commonlib/DecryptSession.o

commonlib/SymmetricCipher.o: commonlib/SymmetricCipher.cpp commonlib/SymmetricCipher.h
	g++ -c -g commonlib/SymmetricCipher.cpp -o commonlib/SymmetricCipher.o

commonlib/SignatureVerifier.o: commonlib/SignatureVerifier.cpp commonlib/SignatureVerifier.h
	g++ -c -g commonlib/SignatureVerifier.cpp -o commonlib/SignatureVerifier.o

commonlib/SignatureMaker.o: commonlib/SignatureMaker.cpp commonlib/SignatureMaker.h
	g++ -c -g commonlib/SignatureMaker.cpp -o commonlib/SignatureMaker.o

commonlib/DynamicArray.o: commonlib/DynamicArray.cpp commonlib/DynamicArray.h
	g++ -c -g commonlib/DynamicArray.cpp -o commonlib/DynamicArray.o

clean:
	rm -f client server *.o commonlib/*.o database.sqlite3
