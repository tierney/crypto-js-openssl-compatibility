
#pragma once

#include <string>

namespace cryptagram {

const int kKeyLen = 32;
const int kSaltLen = 16;

class Key {
 public:
  Key(int nrounds) : nrounds_(nrounds), len_(kKeyLen) {}

  ~Key() {}

  unsigned char* Generate(const std::string& password,
                          unsigned char* salt);

  static void Print(unsigned char* key, int key_len);

 private:

  int nrounds_;
  int len_;
};

}
