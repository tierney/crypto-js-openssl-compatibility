#include <cstdio>
#include <iostream>
#include <vector>
#include <string>

#include "crypto.h"
#include "base64.h"

int main(int argc, char** argv) {
  if (argc != 3) {
    std::cerr << "Expected usage:\n  " << argv[0] << " "
              << "\"Message\" \"Password\"" << std::endl;
    return 1;
  }

  scoped_ptr<cryptagram::BlockCipher> bc;
  for (int i = 0; i < 10; i++) {
    bc.reset(new cryptagram::BlockCipher());

    std::string output;

    bc->Encrypt(argv[1], argv[2], &output);
    std::cout << base64_encode(output) << std::endl;

    bc.reset(new cryptagram::BlockCipher());
    std::string final;
    bc->Decrypt(output, argv[2], &final);

    std::cout << final << std::endl;
    if (final != argv[1]) {
      bc->PrintKey();
      bc->PrintSalt();
    }
  }
  return 0;
}
