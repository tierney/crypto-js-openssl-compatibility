/*!
 * Simple AES
 * Brendan Long
 * March 29, 2010
 *
 * Simplified encryption and decryption using OpenSSL's AES library.
 * Remember to compile with -lcrypto and link against the library
 * g++ (your stuff) -lcrypto simpleAes.cpp (or simpleAes.o)
 *
 * Implementation note: Using the default ivec (0) is not secure. For
 *                      the full security that AES offers, use a different
 *                      ivec each time (it does not need to be secret,
 *                      just different.
 *
 * This code is released into the public domain. Yada yada..
 * Read this for details: http://creativecommons.org/licenses/publicdomain/
 *
 * If for some reason public domain isn't good enough, you may use, alter,
 * distribute or do anything else you want with this code with no restrictions.
 */

#include <openssl/aes.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include "base64.h"
bool seed = true;

/*!
 * Encrypts a string using AES with a 256 bit key
 * Note: If the key is less than 32 bytes, it will be null padded.
 *       If the key is greater than 32 bytes, it will be truncated
 * \param in The string to encrypt
 * \param key The key to encrypt with
 * \return The encrypted data
 */
std::string aes_encrypt(std::string in, std::string key){

    // Seed the random number generator once
    if(seed){
        srand( (unsigned int) time(NULL));
        seed = false;
    }

    // Generate a random ivec
    unsigned char ivec[16];
    for(int i=0; i<16; i++){
        ivec[i] = (unsigned char) rand();
    }

     // Round up to AES_BLOCK_SIZE
    size_t textLength = ((in.length() / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

    // Always pad the key to 32 bits.. because we can
    if(key.length() < 32){
        key.append(32 - key.length(), '\0');
    }

    // Get some space ready for the output
    unsigned char *output = new unsigned char[textLength];

    // Generate a key
    AES_KEY *aesKey = new AES_KEY;
    AES_set_encrypt_key((unsigned char*)key.c_str(), 256, aesKey);

    // Encrypt the data
    AES_cbc_encrypt((unsigned char*)in.c_str(), output, in.length() + 1, aesKey, ivec, AES_ENCRYPT);

    // Make the data into a string
    std::string ret((char*) output, textLength);

    // Add the ivec to the front
    ret = std::string((char*)ivec, 16) + ret;

    // Clean up
    delete output;
    delete aesKey;

    return ret;
}

/*!
 * Decrypts a string using AES with a 256 bit key
 * Note: If the key is less than 32 bytes, it will be null padded.
 *       If the key is greater than 32 bytes, it will be truncated
 * \param in The string to decrypt
 * \param key The key to decrypt with
 * \return The decrypted data
 */
std::string aes_decrypt(std::string in, std::string key){

    // Get the ivec from the front
    unsigned char ivec[16];
    for(int i=0;i<16; i++){
        ivec[i] = in[i];
    }

    in = in.substr(16);

    // Always pad the key to 32 bits.. because we can
    if(key.length() < 32){
        key.append(32 - key.length(), '\0');
    }

    // Create some space for output
    unsigned char *output = new unsigned char[in.length()];

    // Generate a key
    AES_KEY *aesKey = new AES_KEY;
    AES_set_decrypt_key((unsigned char*)key.c_str(), 256, aesKey); // key length is in bits, so 32 * 8 = 256

    // Decrypt the data
    AES_cbc_encrypt((unsigned char*)in.c_str(), output, in.length(), aesKey, ivec, AES_DECRYPT);

    // Make the output into a string
    std::string ret((char*) output);

    // Clean up
    delete output;
    delete aesKey;

    return ret;
}

int main() {
  std::cout << aes_encrypt("abcd", "Secret Passphrase") << std::endl;
  return 0;
}
