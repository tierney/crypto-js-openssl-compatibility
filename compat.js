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

function hex2a(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}
var openSSLEncrypted = "cBctJ8SksVgEDakMgsuXKA=="
var openSSLEncrypted = "U2FsdGVkX19lZFJa0tLh5jZfr/n3Fuk7pcRkV8oV7BU=";
// var openSSLEncrypted = "iABowfppI8t5fkASASgoFogAaMH6aSPLeX5AEgEoKBY=";
// var openSSLEncrypted = "Edw/kVwYlqRPrQOSM2nQIBHcP5FcGJakT60DkjNp0CAK";
var openSSLEncrypted = "rj7OiHGpEUIcQ81+rJAkwQ==";
var decrypted = CryptoJS.AES.decrypt(openSSLEncrypted, "Secret Passphrase");
print ("Decrypted " + decrypted)
print ("          " + hex2a(String(decrypted)))

var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
print (encrypted)
print (encrypted.key)
print (encrypted.iv)
print (encrypted.salt)
print (encrypted.ciphertext)
var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
print (encrypted)
print (encrypted.key)
print (encrypted.iv)
print (encrypted.salt)
print (encrypted.ciphertext)
