#!/bin/bash

KEYDIR="keys/"

if [[ ! -e $KEYDIR ]]; then
	mkdir $KEYDIR
fi

## Public Key Encryption
# privk generation
openssl genrsa -out $KEYDIR/rsa_server_privkey.pem 3072

# pubk generation
openssl rsa -pubout -in $KEYDIR/rsa_server_privkey.pem -out $KEYDIR/rsa_server_pubkey.pem

## Digital Signature
# privk generation
openssl genrsa -out $KEYDIR/rsa_server_digsign_privkey.pem 3072

# pubk generation
openssl rsa -pubout -in $KEYDIR/rsa_server_digsign_privkey.pem -out $KEYDIR/rsa_server_digsign_pubkey.pem
