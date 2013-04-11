#include <iostream>
#include <iomanip>

#include "crypto++/modes.h"
#include "crypto++/aes.h"
#include "crypto++/filters.h"

void Crypto2() {

    //
    // Key and IV setup
    //AES encryption uses a secret key of a variable length (128-bit, 196-bit or 256-
    //bit). This key is secretly exchanged between two parties before communication
    //begins. DEFAULT_KEYLENGTH= 16 bytes
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ];
    byte iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    //
    // String and Sink setup
    //
    std::string plaintext = "Message";
    std::string ciphertext;
    std::string decryptedtext;

    //
    // Dump Plain Text
    //
    std::cout << "Plain Text (" << plaintext.size() << " bytes)" << std::endl;
    std::cout << plaintext;
    std::cout << std::endl << std::endl;

    //
    // Create Cipher Text
    //
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption,
                                                      new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plaintext.c_str() ),
                      plaintext.length() + 1 );
    stfEncryptor.MessageEnd();

    //
    // Dump Cipher Text
    //
    std::cout << "Cipher Text (" << ciphertext.size() << " bytes)" << std::endl;

    for( int i = 0; i < ciphertext.size(); i++ ) {

        std::cout << "0x" << std::hex << (0xFF & static_cast<byte>(ciphertext[i])) << " ";
    }

    std::cout << std::endl << std::endl;

    //
    // Decrypt
    //
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption,
                                                      new CryptoPP::StringSink( decryptedtext ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( ciphertext.c_str() ),
                      ciphertext.size() );
    stfDecryptor.MessageEnd();

    //
    // Dump Decrypted Text
    //
    std::cout << "Decrypted Text: " << std::endl;
    std::cout << decryptedtext;
    std::cout << std::endl << std::endl;

}

// void crypto()
// {
//     SecByteBlock key(16);
//     int32_t plain[4] = { 0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56 }, cipher[4];
//     int32_t* keyBuf = (int32_t*) key.BytePtr();

//     keyBuf[0] = 1885434739;
//     keyBuf[1] = 2003792484;
//     keyBuf[2] = 0;
//     keyBuf[3] = 0;

//     cout << "plain = [" << plain[0] << ", " << plain[1] << ", " << plain[2] << ", " << plain[3] << "]\n";

//     cout << "key = [" << keyBuf[0] << ", " << keyBuf[1] << ", " << keyBuf[2] << ", " << keyBuf[3] << "]\n";

//     CBC_Mode<AES>::Encryption e;
//     e.SetKey(key, key.size());

//     StringSource((const byte*) plain, 16, true, new StreamTransformationFilter( e, new ArraySink((byte*)cipher, 16) ) );

//     cout << "cipher = [" << cipher[0] << ", " << cipher[1] << ", " << cipher[2] << ", " << cipher[3] << "]\n";

// }

int main(int argc, char** argv) {
  Crypto2();
  return 0;
}
