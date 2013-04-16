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

#define KEK_KEY_LEN  20


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

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
int aes_init(unsigned char *key_data, int key_data_len,
             unsigned char *salt,
             EVP_CIPHER_CTX *e_ctx,
             EVP_CIPHER_CTX *d_ctx)
{
  int i, nrounds = 1000;
  /*
   * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
   * nrounds is the number of times the we hash the material. More rounds are more secure but
   * slower.
   */
  unsigned char *out = (unsigned char *) malloc(sizeof(unsigned char) * 32);
  i = PKCS5_PBKDF2_HMAC_SHA1(reinterpret_cast<char *>(key_data), key_data_len,
                             salt, 16,
                             nrounds,
                             32, out);
  std::cout << "Key:";
  for (int ki = 0; ki < 32; ki++) {
    printf("%x ", out[ki]);
  }
  std::cout << std::endl;

  const EVP_CIPHER *cipher= EVP_aes_256_cbc();

  // TODO(tierney): Setup the IV.
  int aiv[] = {
    66232222, 1667193543, 844613033, 139220358
  };
  std::string siv;
  StringyInt(aiv, 4, &siv);
  std::vector<unsigned char> iv_for_init;
  iv_for_init.reserve(16);
  hex_to_uchar(siv, &iv_for_init);

  std::cout << "IV: ";
  for (int ki = 0; ki < 16; ki++) {
    printf("%x ", iv_for_init[ki]);
  }
  std::cout << std::endl;

  EVP_EncryptInit_ex(e_ctx, cipher, NULL, out, &iv_for_init[0]);
  // EVP_EncryptInit_ex(e_ctx, cipher, NULL, NULL, NULL);
  // EVP_EncryptInit_ex(e_ctx, NULL, NULL, key, iv);


  // EVP_CIPHER_CTX_init(d_ctx);
  EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, out, &iv_for_init[0]);

  return 0;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len)
{
  /* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
  int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
  std::cout << "ctx len: " << c_len << std::endl;
  unsigned char *ciphertext = (unsigned char *)malloc(c_len);

  /* allows reusing of 'e' for multiple encryption cycles */
  // EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

  /* update ciphertext, c_len is filled with the length of ciphertext generated,
    *len is the size of plaintext in bytes */
  EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);
  std::cout << "Wrote this many bytes: " << c_len << std::endl;
  std::cout << "Read this many bytes: " << *len << std::endl;

  /* update ciphertext with the final remaining bytes */
  EVP_CipherFinal_ex(e, ciphertext+c_len, &f_len);
  std::cout << "Final Write of bytes: " << f_len << std::endl;
  *len = c_len + f_len;

  return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len)
{
  /* because we have padding ON, we must allocate an extra cipher block size of memory */
  int p_len = *len, f_len = 0;
  unsigned char *plaintext = (unsigned char *)malloc(p_len + AES_BLOCK_SIZE);

  EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
  EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
  EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);

  *len = p_len + f_len;
  return plaintext;
}

int main(int argc, char **argv)
{
  /* "opaque" encryption, decryption ctx structures that libcrypto uses to record
     status of enc/dec operations */

  // TODO(tierney): Use the built-in _new() and _cleanup() functions.
  //
  EVP_CIPHER_CTX* en = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX* de = EVP_CIPHER_CTX_new();

  /* 8 bytes to salt the key_data during key generation. This is an example of
     compiled in salt. We just read the bit pattern created by these two 4 byte
     integers on the stack as 64 bits of contigous salt material -
     ofcourse this only works if sizeof(int) >= 4 */
  int salt[] = {
    -337252981, 1983954810, -1775065387, 845219142
  };
  std::string ssalt;
  StringyInt(salt, 4, &ssalt);

  // salt[7] = '\0';
  unsigned char *key_data;
  int key_data_len, i;
  // char *input[] = {"a", "abcd", "this is a test", "this is a bigger test",
  //                  "\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",
  //                  NULL};
  // char *input[] = {"01234567 \n01234567 \n abcdef", NULL};
  char *input[] = {"abcd", NULL};


  /* the key_data is read from the argument list */
  key_data = (unsigned char *)argv[1];
  key_data_len = strlen(argv[1]);

  std::vector<unsigned char> salt_for_init;
  salt_for_init.reserve(16);
  hex_to_uchar(ssalt, &salt_for_init);

  /* gen key and iv. init the cipher ctx object */
  if (aes_init(key_data, key_data_len,
               &salt_for_init[0], en, de)) {
    printf("Couldn't initialize AES cipher\n");
    return -1;
  }

  /* encrypt and decrypt each input string and compare with the original */
  for (i = 0; input[i]; i++) {
    char *plaintext;
    unsigned char *ciphertext;
    int olen, len;

    /* The enc/dec functions deal with binary data and not C strings. strlen()
       will return length of the string without counting the '\0' string
       marker. We always pass in the marker byte to the encrypt/decrypt
       functions so that after decryption we end up with a legal C string */
    olen = len = strlen(input[i])+1;
    std::cout << "aes_encrypt's len: " << len << std::endl;

    ciphertext = aes_encrypt(en, (unsigned char *)input[i], &len);
    // std::cout << "Cipher: " << ciphertext << std::endl;

    std::string to_encode = "Salted__";
    to_encode.append(reinterpret_cast<char *>(salt), 16);

    std::cout << "Ciphertext: ";
    for (int ki = 0; ki < len; ki++) {
      printf("%x ", ciphertext[ki]);
    }
    std::cout << std::endl;

    to_encode.append(reinterpret_cast<char *>(ciphertext));
    std::cout << base64_encode(to_encode) << std::endl;
    // std::cout << "Cipher: " << (to_encode) << std::endl;

    plaintext = (char *)aes_decrypt(de, ciphertext, &len);

    if (strncmp(plaintext, input[i], olen))
      printf("FAIL: enc/dec failed for \"%s\"\n", input[i]);

    free(ciphertext);
    free(plaintext);
  }

  EVP_CIPHER_CTX_free(en);
  EVP_CIPHER_CTX_free(de);

  return 0;
}
