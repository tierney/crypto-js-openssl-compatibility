#include <cstdio>
#include <iostream>
#include <vector>
#include <string>

#include "crypto.h"
#include "base64.h"

int main(int argc, char** argv) {
  cryptagram::BlockCipher bc;
  std::string output;

  if (argc != 3) {
    std::cerr << "Expected usage:\n  " << argv[0] << " "
              << "\"Message\" \"Password\"" << std::endl;
    return 1;
  }

  bc.Encrypt(argv[1], argv[2],&output);
  std::cout << base64_encode(output) << std::endl;

  std::string final;
  bc.Decrypt(output, argv[2], &final);

  std::cout << final << std::endl;
  return 0;
}
