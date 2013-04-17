#!/bin/bash

V8=/scratch1/repos/v8/out/x64.release/shell
FILES=~/repos/crypto-js/src/{core,x64-core,sha512,md5,hmac,pbkdf2}.js

${V8} \
    /home/tierney/repos/crypto-js/src/core.js \
    /home/tierney/repos/crypto-js/src/x64-core.js \
    /home/tierney/repos/crypto-js/src/sha512.js \
    /home/tierney/repos/crypto-js/src/md5.js \
    /home/tierney/repos/crypto-js/src/sha1.js \
    /home/tierney/repos/crypto-js/src/hmac.js \
    /home/tierney/repos/crypto-js/src/pbkdf2.js \
    /home/tierney/repos/crypto-js/src/evpkdf.js \
    /home/tierney/repos/crypto-js/src/enc-base64.js \
    /home/tierney/repos/crypto-js/src/cipher-core.js \
    /home/tierney/repos/crypto-js/src/aes.js \
    compat.js
