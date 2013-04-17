#pragma once

#include <string>
#include "base/memory/scoped_ptr.h"

namespace cryptagram {

const char *kOpenSSLMagic = "Salted__";

class OpenSSLFormat {
 public:
  OpenSSLFormat();

 private:
  scoped_array<unsigned char> salt_;
  std::string cipher_;
};

}
