#include <cstdio>
#include <iostream>
#include <string.h>
#include <cstdlib>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <cassert>
#include "base64.h"
#include <iomanip>
#include <sstream>
#include <fstream>
#include <vector>
#include <string>

struct HexCharStruct
{
  unsigned char c;
  HexCharStruct(unsigned char _c) : c(_c) { }
};

inline std::ostream& operator<<(std::ostream& o, const HexCharStruct& hs)
{
  return (o << std::hex << (int)hs.c);
}

inline HexCharStruct hex(unsigned char _c)
{
  return HexCharStruct(_c);
}

template< typename T >
std::string int_to_hex( T i )
{
  std::stringstream stream;
  stream << ""                          // May want to prepend 0x.
         << std::setfill ('0') << std::setw(sizeof(T)*2)
         << std::hex << i;
  return stream.str();
}

bool StringyInt(int *input, int slen, std::string *out) {
  assert(out != NULL);
  out->clear();

  for (int i = 0; i < slen; i++) {
    out->append(int_to_hex<int>(input[i]));
  }

  return true;
}

bool hex_to_uchar(const std::string& hex_chars,
                  std::vector<unsigned char>* bytes) {
  assert(bytes != NULL);
  bytes->clear();
  bytes->reserve(16);

  // Split every two.
  char frag[3];
  frag[2] = '\0';
  std::string hex_chars_to_stream;
  for (int i = 0; i < hex_chars.length(); i += 2) {
    memcpy(frag, hex_chars.c_str() + i, 2);
    hex_chars_to_stream.append(frag);
    if (i + 2 == hex_chars.length()) {
      break;
    }
    hex_chars_to_stream.append(" ");
  }

  std::istringstream hex_chars_stream(hex_chars_to_stream);

  unsigned int c;
  while (hex_chars_stream >> std::hex >> c)
  {
    bytes->push_back(c);
  }
  return true;
}


int main(int argc, char** argv) {
  // Salt init
  int salt[] = {1974066912, 2023546023, 329189918, -2043528558};
  std::string ssalt;
  StringyInt(salt, 4, &ssalt);
  std::vector<unsigned char> salt_for_init;
  salt_for_init.reserve(16);
  hex_to_uchar(ssalt, &salt_for_init);

  // Human password
  unsigned char password[] = "Secret Passphrase\0";

  // Derive key from salt and password.
  int nrounds = 1000;
  unsigned char *key = (unsigned char *) malloc(sizeof(unsigned char) * 32);
  PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<char *>(password),
                             18,
                             &salt_for_init[0], 16,
                             nrounds,
                             32,
                             key);
  std::cout << "Key: ";
  for (int ki = 0; ki < 32; ki++) {
    printf("%x ", key[ki]);
  }
  std::cout << std::endl;

  // IV generated.
  int aiv[] = {1416613809, -1700576067, -1610198381, -40862394};
  std::string siv;
  StringyInt(aiv, 4, &siv);
  std::vector<unsigned char> iv_for_init;
  iv_for_init.reserve(16);
  hex_to_uchar(siv, &iv_for_init);

  std::cout << "Iv: ";
  for (int ki = 0; ki < 16; ki++) {
    printf("%x ", iv_for_init[ki]);
  }
  std::cout << std::endl;

  std::string message = "abcd";

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher= EVP_aes_256_cbc();
  unsigned char *out = (unsigned char *) malloc(sizeof(unsigned char) * 32);
  EVP_EncryptInit_ex(ctx, cipher, NULL,  out, &iv_for_init[0]);

  int alen = 0;
  int *len = &alen;
  *len = message.length() + 1;

  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);
  EVP_EncryptUpdate(ctx, ciphertext, &c_len,
                    reinterpret_cast<const unsigned char*>(message.c_str()),
                    *len);

  EVP_CipherFinal_ex(ctx, ciphertext+c_len, &f_len);

  for (int j = 0; j < f_len; j++) {
    std::cout << hex(static_cast<char>(ciphertext[j]));
  }
  std::cout << std::endl;

  return 0;
}
