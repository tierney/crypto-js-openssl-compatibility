#pragma once

#include "base/memory/scoped_ptr.h"
#include <openssl/evp.h>
#include <string>

namespace cryptagram {

class BlockCipher {
 public:
  BlockCipher()
      : encrypt_(EVP_CIPHER_CTX_new()), decrypt_(EVP_CIPHER_CTX_new()),
        cipher_(EVP_aes_256_cbc()), nrounds_(1) {}


  bool Encrypt(const std::string& input, const std::string& password,
               std::string* output);

  bool Decrypt(const std::string& input, const std::string& password,
               std::string* output);

 private:
  void InitEncrypt(const std::string& password);
  void InitDecrypt(const std::string& password,
                   const std::string& iv);

  scoped_ptr<EVP_CIPHER_CTX> encrypt_;
  scoped_ptr<EVP_CIPHER_CTX> decrypt_;

  scoped_array<unsigned char> salt_;
  scoped_array<unsigned char> iv_;

  scoped_array<unsigned char> key_;

  scoped_array<const EVP_CIPHER> cipher_;

  int nrounds_;
};

}
