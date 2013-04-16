all:
	clang++ -o file_util.o -Wall -c file_util.cc
	clang++ -o base64.o -Wall -c base64.cc
	clang++ -o cryptossl -g -O0 -Wall cryptossl.cc -lcrypto base64.o -ldl
	# clang++ -I../v8/include v8.cc -o hello_world ../v8/out/x64.release/libv8_{base,snapshot}.a -lpthread -L. -lfile_util.o

clean:
	rm -f cryp cryptossl *.o hello_world
	rm -rf cryptossl.dSYM
