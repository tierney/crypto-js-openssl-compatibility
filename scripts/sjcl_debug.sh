#!/bin/bash

V8=/scratch1/repos/v8/out/x64.release/shell

${V8} /home/tierney/repos/sjcl/core/sjcl.js \
    /home/tierney/repos/sjcl/core/aes.js \
    /home/tierney/repos/sjcl/core/bitArray.js \
    /home/tierney/repos/sjcl/core/bn.js \
    /home/tierney/repos/sjcl/core/cbc.js \
    /home/tierney/repos/sjcl/core/ccm.js \
    /home/tierney/repos/sjcl/core/codecBase64.js \
    /home/tierney/repos/sjcl/core/codecBytes.js \
    /home/tierney/repos/sjcl/core/codecHex.js \
    /home/tierney/repos/sjcl/core/codecString.js \
    /home/tierney/repos/sjcl/core/convenience.js \
    /home/tierney/repos/sjcl/core/ecc.js \
    /home/tierney/repos/sjcl/core/gcm.js \
    /home/tierney/repos/sjcl/core/hmac.js \
    /home/tierney/repos/sjcl/core/ocb2.js \
    /home/tierney/repos/sjcl/core/pbkdf2.js \
    /home/tierney/repos/sjcl/core/sha256.js \
    /home/tierney/repos/sjcl/core/random.js \
    /home/tierney/repos/sjcl/core/sha1.js \
    /home/tierney/repos/sjcl/core/sha512.js \
    /home/tierney/repos/sjcl/core/srp.js \
    sjcl_debug.js
