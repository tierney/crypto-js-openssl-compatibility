var salt = CryptoJS.lib.WordArray.random(128/8);

var salt = 'e10f6ec5f86b50fc8802d1be05e4949d';

var key = CryptoJS.PBKDF2("secret", salt, { keySize: 128/32,
                                            iterations: 1000 });

print (salt);
print (String(key).length);
var passphrase = CryptoJS.enc.Hex.stringify(key);
var encrypted = CryptoJS.AES.encrypt("Message", passphrase);
print (encrypted);
print (String(encrypted).length);
SerializableCipher.encrypt.call(this, cipher, message, derivedParams.key, cfg);
