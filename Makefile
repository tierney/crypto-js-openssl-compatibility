all:
	clang++ -o crypto crypto.cc -lcryptopp
	clang++ -o base64.o -Wall -c base64.cc
	clang++ -o cryptossl -g -O0 -Wall cryptossl.cc -L../openssl-1.0.1e -lcrypto base64.o -ldl
	clang++ -o cryp -Wall cryptossl2.cc -lcrypto base64.o
