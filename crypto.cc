#include "crypto.h"

namespace cryptagram {

void BlockCipher::Init(const std::string& salt, const std::string& password) {
  EVP_BytesToKey(cipher_.get(),
                 EVP_md5(),
                 reinterpret_cast<const unsigned char*>(salt.c_str()),
                 reinterpret_cast<const unsigned char*>(password.c_str()),
                 password.length(),
                 nrounds_,
                 key_.get(),
                 iv_.get());
  EVP_EncryptInit_ex(encrypt_.get(), cipher_.get(), NULL,
                     reinterpret_cast<const unsigned char*>(key_.get()),
                     reinterpret_cast<const unsigned char*>(iv_.get()));
  EVP_EncryptInit_ex(decrypt_.get(), cipher_.get(), NULL,
                     reinterpret_cast<const unsigned char*>(key_.get()),
                     reinterpret_cast<const unsigned char*>(iv_.get()));

}

}
