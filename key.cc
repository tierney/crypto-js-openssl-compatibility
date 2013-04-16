#include "key.h"

#include <iostream>
#include <cstdlib>
#include <cstdio>

#include <openssl/evp.h>

namespace cryptagram {

unsigned char* Key::Generate(const std::string& password,
                             unsigned char* salt) {

  unsigned char *out = (unsigned char *) malloc(sizeof(unsigned char) * kKeyLen);

  PKCS5_PBKDF2_HMAC_SHA1(password.c_str(),
                         password.length(),
                         salt,
                         kSaltLen,
                         nrounds_,
                         kKeyLen,
                         out);

  return out;
}

void Key::Print(unsigned char* key, int key_len) {
  std::cout << "Key:";
  for (int ki = 0; ki < key_len; ki++) {
    printf("%x ", key[ki]);
  }
  std::cout << std::endl;
}

}
