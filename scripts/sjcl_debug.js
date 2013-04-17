    var key = [1885434739, 2003792484, 1885434739, 2003792484];
    var plain = [0x93C467E3,0x7DB0C7A4,0xD1BE3F81,0x0152CB56];
    print("plain = "+plain);
    print("key = "+key);
    var cipher = (new sjcl.cipher.aes(key)).encrypt(plain);
    print("cipher = "+cipher);
