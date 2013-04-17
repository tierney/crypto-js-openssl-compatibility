#include <cstdio>
#include <iostream>
#include <vector>
#include <string>

#include "crypto.h"
#include "base64.h"

int main(int argc, char** argv) {
  cryptagram::BlockCipher bc;
  std::string output;

  bc.Encrypt(argv[1], "Secret Passphrase", &output);
  std::cout << base64_encode(output) << std::endl;

  std::string final;
  bc.Decrypt(output, "Secret Passphrase", &final);

  std::cout << final << std::endl;
  return 0;
}
