all: key mycrypto
	clang++ -o file_util.o -Wall -c file_util.cc
	clang++ -o base64.o -Wall -c base64.cc
	clang++ -o cryptossl -g -O0 -Wall -std=c++11 cryptossl.cc -L../openssl-1.0.1e -lcrypto base64.o -ldl
	clang++ -o main -g -O0 -Wall -std=c++11 main.cc -L../openssl-1.0.1e -lcrypto base64.o mycrypto.o -ldl -I.
	# clang++ -I../v8/include v8.cc -o hello_world ../v8/out/x64.release/libv8_{base,snapshot}.a -lpthread -L. -lfile_util.o

mycrypto:
	clang++ -o mycrypto.o -Wall -c crypto.cc -I.

key:
	clang++ -o key.o -Wall -c key.cc

clean:
	rm -f cryp cryptossl *.o hello_world
	rm -rf cryptossl.dSYM
