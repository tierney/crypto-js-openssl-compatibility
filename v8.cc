
#include <v8.h>

#include "file_util.h"

using namespace v8;

int main(int argc, char* argv[]) {

  // Create a stack-allocated handle scope.
  HandleScope handle_scope;

  // Create a new context.
  Persistent<Context> context = Context::New();

  // Enter the created context for compiling and
  // running the hello world script.
  Context::Scope context_scope(context);

  std::string v8;
  ReadFileToString("~/repos/cryptojs/components/core.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/x64-core.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/sha512.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/md5.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/sha1.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/hmac.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/pbkdf2.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/evpkdf.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/enc-base64.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/cipher-core.js", &v8);
  ReadFileToString("~/repos/cryptojs/components/aes.js", &v8);

  v8.append(";\nCryptoJS.AES.decrypt('U2FsdGVkX1/t6mZvWb+7AJu8PtiPBgFGveegemEj9YFsnkcFLTPw8R87sq0nOZDX', 'Secret Passphrase');");
  // Create a string containing the JavaScript source code.
  Handle<String> source = String::New(v8.c_str());

  // Compile the source code.
  Handle<Script> script = Script::Compile(source);

  // Run the script to get the result.
  Handle<Value> result = script->Run();

  // Dispose the persistent context.
  context.Dispose();

  // Convert the result to an ASCII string and print it.
  String::AsciiValue ascii(result);
  printf("%s\n", *ascii);
  return 0;
}
