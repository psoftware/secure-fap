#include "commonlib/commonlib.h"
#include <iostream>

using namespace std;
#define CHUNK_SIZE 32

unsigned int divide_upper(unsigned int dividend, unsigned int divisor)
{
    return 1 + ((dividend - 1) / divisor);
}

int main(int argc, char **argv)
{
	unsigned char key[16];
	unsigned char plaintext_0[256];
	unsigned char *ciphertext_0;
	unsigned char *plaintext_1;

	printf("plaintext_0: \n");
	print_hex(plaintext_0, 256);
	printf("------------------\n");

	SymmetricCipher sc(EVP_aes_128_cbc(),key,NULL);
	unsigned int chunk_cipherlen = sc.encrypt(plaintext_0, 256, &ciphertext_0);

	printf("ciphertext_0: \n");
	print_hex(ciphertext_0, chunk_cipherlen);
	printf("------------------\n");

	unsigned int chunk_plainlen = sc.decrypt(ciphertext_0, chunk_cipherlen, &plaintext_1);

	printf("plaintext_1: \n");
	print_hex(plaintext_1, chunk_plainlen);
	printf("------------------\n");

	return 0;
}