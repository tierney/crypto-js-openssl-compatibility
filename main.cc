#include <cstdio>
#include <iostream>
#include <vector>
#include <string>

#include "crypto.h"

int main(int argc, char** argv) {
  cryptagram::BlockCipher bc;
  std::string output;
  bc.Encrypt("Message", "Secret Passphrase", &output);
  return 0;
}
