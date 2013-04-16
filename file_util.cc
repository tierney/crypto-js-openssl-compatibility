#include "file_util.h"

#include <errno.h>

FILE* OpenFile(const std::string& filename, const char* mode) {
  FILE* result = NULL;
  do {
    result = fopen(filename.c_str(), mode);
  } while (!result && errno == EINTR);
  return result;
}

bool CloseFile(FILE* file) {
  if (file == NULL)
    return true;
  return fclose(file) == 0;
}

bool ReadFileToString(const std::string& path, std::string* contents) {
  FILE* file = OpenFile(path, "rb");
  if (!file) {
    return false;
  }

  char buf[1 << 16];
  size_t len;
  while ((len = fread(buf, 1, sizeof(buf), file)) > 0) {
    if (contents)
      contents->append(buf, len);
  }
  CloseFile(file);

  return true;
}
