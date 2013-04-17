print (CryptoJS.SHA512("hello world"));
var salt = CryptoJS.lib.WordArray.random(128/8);
var key512Bits1000Iterations = CryptoJS.PBKDF2("Secret Passphrase", salt, { keySize: 128/32, iterations: 1000 });

print (key512Bits1000Iterations);
    var encrypted = CryptoJS.AES.encrypt("Message", "Secret Passphrase");

    var decrypted = CryptoJS.AES.decrypt(encrypted, "Secret Passphrase");
print (decrypted);
print (CryptoJS.enc.Hex.parse(decrypted));
print (CryptoJS.enc.Hex.stringify(decrypted));

    var key = CryptoJS.enc.Hex.parse('000102030405060708090a0b0c0d0e0f');
    var iv  = CryptoJS.enc.Hex.parse('101112131415161718191a1b1c1d1e1f');

    var encrypted = CryptoJS.AES.encrypt("Message", key, { iv: iv });
print ('Here we go...');
var msg = hex2a('93c467e37db0c7a4d1be3f810152cb56');
print ('Msg ' + msg);
var key = hex2a('1885434739200379248418854347392003792484');
print ('Encrypt ' + key);
var encrypted = CryptoJS.AES.encrypt(msg, key);
print ('Done');
print (encrypted);

print (encrypted.key);

function hex2a(hex) {
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

print (hex2a(String(decrypted)));
print (hex2a('32343630'));
print (CryptoJS.AES.decrypt(encrypted, key, {iv:iv}));
