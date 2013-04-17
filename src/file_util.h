#pragma once

#include <string>

FILE* OpenFile(const std::string& filename, const char* mode);

bool CloseFile(FILE* file);

bool ReadFileToString(const std::string& path, std::string* contents);
