#include "crypto.h"

#include <cassert>
#include <openssl/aes.h>

namespace cryptagram {

const int kSaltLen = 8;

// void BlockCipher::Init(const std::string& salt, const std::string& password) {
//   EVP_BytesToKey(cipher_.get(),
//                  EVP_md5(),
//                  reinterpret_cast<const unsigned char*>(salt.c_str()),
//                  reinterpret_cast<const unsigned char*>(password.c_str()),
//                  password.length(),
//                  nrounds_,
//                  key_.get(),
//                  iv_.get());
//   EVP_EncryptInit_ex(encrypt_.get(), cipher_.get(), NULL,
//                      reinterpret_cast<const unsigned char*>(key_.get()),
//                      reinterpret_cast<const unsigned char*>(iv_.get()));
//   EVP_EncryptInit_ex(decrypt_.get(), cipher_.get(), NULL,
//                      reinterpret_cast<const unsigned char*>(key_.get()),
//                      reinterpret_cast<const unsigned char*>(iv_.get()));
// }

bool BlockCipher::Encrypt(const std::string& input,
                          const std::string& password,
                          std::string* output) {
  assert(output != NULL);
  scoped_array<unsigned char> salt(new unsigned char[kSaltLen]);
  EVP_BytesToKey(cipher_.get(),
                 EVP_md5(),
                 salt.get(),
                 reinterpret_cast<const unsigned char*>(password.c_str()),
                 password.length(),
                 nrounds_,
                 key_.get(),
                 iv_.get());
  EVP_EncryptInit_ex(encrypt_.get(),
                     cipher_.get(),
                     NULL,
                     key_.get(),
                     iv_.get());
  int c_len = input.length() + AES_BLOCK_SIZE;
  int f_len = 0;
  scoped_array<unsigned char> ciphertext(new unsigned char[c_len]);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
   *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(encrypt_.get(), ciphertext.get(), &c_len,
                    reinterpret_cast<const unsigned char*>(password.c_str()),
                    input.length());

  /* update ciphertext with the final remaining bytes */
  EVP_CipherFinal_ex(encrypt_.get(), ciphertext.get() + c_len, &f_len);

  output->clear();
  output->append(reinterpret_cast<const char *>(ciphertext.get()),
                 c_len + f_len);
  return true;
}

}
