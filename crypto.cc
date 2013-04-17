#include "crypto.h"

#include <cassert>
#include <iostream>
#include <openssl/aes.h>
#include <openssl/rand.h>

namespace cryptagram {

BlockCipher::BlockCipher()
      : encrypt_(EVP_CIPHER_CTX_new()), decrypt_(EVP_CIPHER_CTX_new()),
        cipher_(EVP_aes_256_cbc()),
        digest_(EVP_md5()),
        salt_(new unsigned char[kSaltLen]),
        iv_(new unsigned char[kIvLen]),
        key_(new unsigned char[EVP_MAX_KEY_LENGTH]),
        nrounds_(1) {
}

BlockCipher::~BlockCipher() {
  EVP_CIPHER_CTX_cleanup(encrypt_.get());
  EVP_CIPHER_CTX_cleanup(decrypt_.get());
}

bool BlockCipher::Encrypt(const std::string& input,
                          const std::string& password,
                          std::string* output) {
  assert(output != NULL);

  InitEncrypt(password);

  int c_len = input.length() + 1 + AES_BLOCK_SIZE;
  int f_len = 0;

  scoped_array<unsigned char> ciphertext(new unsigned char[c_len]);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
   *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(encrypt_.get(),
                    ciphertext.get(),
                    &c_len,
                    reinterpret_cast<const unsigned char *>(input.c_str()),
                    input.length());

  /* update ciphertext with the final remaining bytes */
  EVP_CipherFinal_ex(encrypt_.get(), ciphertext.get() + c_len, &f_len);

  // OpenSSL format. Magic number is "Salted__" followed by the salt and then
  // the ciphertext.
  output->clear();
  output->append("Salted__");
  output->append(reinterpret_cast<const char *>(salt_.get()));
  output->append(reinterpret_cast<const char *>(ciphertext.get()),
                 c_len + f_len);
  return true;
}

bool BlockCipher::Decrypt(const std::string& input,
                          const std::string& password,
                          std::string* output) {
  assert(output != NULL);

  int p_len = input.length() - 16, f_len = 0;
  scoped_array<unsigned char> plaintext(new unsigned char[p_len + AES_BLOCK_SIZE]);

  InitDecrypt(input, password);

  scoped_array<unsigned char> input_ctx(new unsigned char[p_len]);
  strncpy(reinterpret_cast<char *>(input_ctx.get()), input.substr(16).c_str(), p_len);

  EVP_DecryptUpdate(decrypt_.get(),
                    plaintext.get(),
                    &p_len,
                    reinterpret_cast<const unsigned char *>(input_ctx.get()),
                    p_len);
  EVP_DecryptFinal_ex(decrypt_.get(),
                      plaintext.get() + p_len,
                      &f_len);

  output->clear();
  output->append(reinterpret_cast<const char *>(plaintext.get()), p_len + f_len);

  return true;
}

void BlockCipher::InitEncrypt(const std::string& password) {
  RAND_bytes(salt_.get(), 8);

  EVP_BytesToKey(cipher_,
                 digest_,
                 salt_.get(),
                 reinterpret_cast<const unsigned char*>(password.c_str()),
                 password.length(),
                 nrounds_,
                 key_.get(),
                 iv_.get());

  EVP_CIPHER_CTX_init(encrypt_.get());
  EVP_EncryptInit_ex(encrypt_.get(),
                     cipher_,
                     NULL,
                     key_.get(),
                     iv_.get());
}

void BlockCipher::InitDecrypt(const std::string& input, const std::string& password) {
  // Parse the input string for iv and ciphertext.
  strncpy(reinterpret_cast<char *>(salt_.get()), input.substr(8, 8).c_str(), 8);

  EVP_BytesToKey(cipher_,
                 digest_,
                 salt_.get(),
                 reinterpret_cast<const unsigned char*>(password.c_str()),
                 password.length(),
                 nrounds_,
                 key_.get(),
                 iv_.get());


  EVP_CIPHER_CTX_init(decrypt_.get());
  EVP_DecryptInit_ex(decrypt_.get(), cipher_, NULL, key_.get(), iv_.get());
}

}
