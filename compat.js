var salt = CryptoJS.lib.WordArray.random(128/8);

var salt = 'e10f6ec5f86b50fc8802d1be05e4949d';

var key = CryptoJS.PBKDF2("Secret Passphrase", salt, { keySize: 128/32,
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
var openSSLEncrypted = "sNUq0t/UmJTWXUZhiLp67w==";
var openSSLEncrypted = "DbzgjTt3cnWFQWZ3tjuoqD0=";
var openSSLEncrypted = "U2FsdGVkX1/t6mZvWb+7ALDVKtLf1JiU1l1GYYi6eu8=";
// var openSSLEncrypted = "U2FsdGVkX1/t6mZvWb+7AFH0zEYCPskMSlc1Pdz6qRo=";
var openSSLEncrypted = "U2FsdGVkX1/t6mZvWb+7ALDVKtLf1JiU1l1GYYi6eu8=";
var openSSLEncrypted = "U2FsdGVkX1/t6mZvWb+7AFcb+yea5S1qXPkvakgiGq4gDCZVDpyEk62XBdSlmkLqydPo6LCgnJox";
var openSSLEncrypted = "U2FsdGVkX1/t6mZvWb+7AJu8PtiPBgFGveegemEj9YFsnkcFLTPw8R87sq0nOZDX";
print ("Decrypting: " + openSSLEncrypted);
var decrypted = CryptoJS.AES.decrypt(openSSLEncrypted, "Secret Passphrase");
print ("Decrypted '" + decrypted + "'")
print ("Decrypted '" + String(decrypted) + "'")
print ("          " + hex2a(String(decrypted)))

var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
print ("encrypted: " + encrypted)
print ("encrypted.key: " + encrypted.key)
print ("encrypted.iv: " + encrypted.iv)
print ("encrypted.salt: " + encrypted.salt)
print ("encrypted.ciphertext: " + encrypted.ciphertext)
var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");
print ("encrypted: " + encrypted)
print ("encrypted.key: " + encrypted.key)
print ("encrypted.iv: " + encrypted.iv)
print ("encrypted.salt: " + encrypted.salt)
print ("encrypted.ciphertext:" + encrypted.ciphertext)
