#!/usr/bin/python
#import Crypto

from Crypto.Cipher import AES
import scrypt
import hashlib
from bitcoin import *
import binascii
import base58


# BIP0038 proposal test cases for non-ec multiply mode verified
# Additional test cases verified with bitaddress.org

# TODO:
# verify encrypted privkey checksum before decrypting?


tests = [{'passphrase':'TestingOneTwoThree',
          'expectedpriv':"6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
          'expectedwif':"5KN7MzqK5wt2TP1fQCYyHBtDrXdJuXbUzm4A9rKAteGu3Qi5CVR",
          'expectedaddr':"1Jq6MksXQVWzrznvZzxkV6oY57oWXD9TXB"},
         {'passphrase':'Satoshi',
          'expectedpriv':"6PRNFFkZc2NZ6dJqFfhRoFNMR9Lnyj7dYGrzdgXXVMXcxoKTePPX1dWByq",
          'expectedwif':"5HtasZ6ofTHP6HCwTqTkLDuLQisYPah7aUnSKfC7h4hMUVw2gi5",
          'expectedaddr':"1AvKt49sui9zfzGeo8EyL8ypvAhtR2KwbL"}]

compresstests = [{'passphrase':'TestingOneTwoThree',
                  'expectedpriv':"6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
                  'expectedwif':"L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
                  'expectedaddr':"164MQi977u9GUteHr4EPH27VkkdxmfCvGW"},
                 {'passphrase':'Satoshi',
                  'expectedpriv':"6PYLtMnXvfG3oJde97zRyLYFZCYizPU5T3LwgdYJz1fRhh16bU7u6PPmY7",
                  'expectedwif':"KwYgW8gcxj1JWJXhPSu4Fqwzfhp5Yfi42mdYmMa4XqK7NJxXUSK7",
                  'expectedaddr':"1HmPbwsvG5qJ3KJfxzsZRZWhbm1xBMuS8B"}]

def bip38_encrypt(privkey,passphrase):
    '''BIP0038 non-ec-multiply encryption. Returns BIP0038 encrypted privkey.'''
    privformat = get_privkey_format(privkey)
    if privformat in ['wif_compressed','hex_compressed']:
        compressed = True
        flagbyte = '\xe0'
        if privformat == 'wif_compressed':
            privkey = encode_privkey(privkey,'hex_compressed')
            privformat = get_privkey_format(privkey)
    if privformat in ['wif', 'hex']:
        compressed = False
        flagbyte = '\xc0'
    if privformat == 'wif':
        privkey = encode_privkey(privkey,'hex')
        privformat = get_privkey_format(privkey)
    pubkey = privtopub(privkey)
    addr = pubtoaddr(pubkey)
    addresshash = hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4]
    key = scrypt.hash(passphrase, addresshash, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    aes = AES.new(derivedhalf2)
    encryptedhalf1 = aes.encrypt(binascii.unhexlify('%0.32x' % (long(privkey[0:32], 16) ^ long(binascii.hexlify(derivedhalf1[0:16]), 16))))
    encryptedhalf2 = aes.encrypt(binascii.unhexlify('%0.32x' % (long(privkey[32:64], 16) ^ long(binascii.hexlify(derivedhalf1[16:32]), 16))))
    encrypted_privkey = ('\x01\x42' + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2)
    encrypted_privkey += hashlib.sha256(hashlib.sha256(encrypted_privkey).digest()).digest()[:4] # b58check for encrypted privkey
    encrypted_privkey = base58.b58encode(encrypted_privkey)
    return encrypted_privkey

def bip38_decrypt(encrypted_privkey,passphrase):
    '''BIP0038 non-ec-multiply decryption. Returns WIF privkey.'''
    d = base58.b58decode(encrypted_privkey)
    d = d[2:]
    flagbyte = d[0:1]
    d = d[1:]
    if flagbyte == '\xc0':
        compressed = False
    if flagbyte == '\xe0':
        compressed = True
    addresshash = d[0:4]
    d = d[4:-4]
    key = scrypt.hash(passphrase,addresshash, 16384, 8, 8)
    derivedhalf1 = key[0:32]
    derivedhalf2 = key[32:64]
    encryptedhalf1 = d[0:16]
    encryptedhalf2 = d[16:32]
    aes = AES.new(derivedhalf2)
    decryptedhalf2 = aes.decrypt(encryptedhalf2)
    decryptedhalf1 = aes.decrypt(encryptedhalf1)
    priv = decryptedhalf1 + decryptedhalf2
    priv = binascii.unhexlify('%064x' % (long(binascii.hexlify(priv), 16) ^ long(binascii.hexlify(derivedhalf1), 16)))
    pub = privtopub(priv)
    if compressed:
        pub = encode_pubkey(pub,'hex_compressed')
        wif = encode_privkey(priv,'wif_compressed')
    else:
        wif = encode_privkey(priv,'wif')
    addr = pubtoaddr(pub)
    if hashlib.sha256(hashlib.sha256(addr).digest()).digest()[0:4] != addresshash:
        print('Addresshash verification failed! Password is likely incorrect.')
    return wif

def runtests():
    for test in tests:
        passphrase = test.get('passphrase')
        expectedpriv = test.get('expectedpriv')
        expectedwif = test.get('expectedwif')
        expectedaddr = test.get('expectedaddr')
        print('Testing %s' %(expectedwif))
        resultpriv = bip38_encrypt(expectedwif,passphrase)
        if resultpriv == expectedpriv:
            print('Encryption Success!')
        decryptedpriv = bip38_decrypt(resultpriv,passphrase)
        if decryptedpriv == expectedwif:
            print('Decryption Success!')
        print('-')*80
        
def compresstest():
    for test in compresstests:
        passphrase = test.get('passphrase')
        expectedpriv = test.get('expectedpriv')
        expectedwif = test.get('expectedwif')
        expectedaddr = test.get('expectedaddr')
        print('Testing %s' %(expectedwif))
        resultpriv = bip38_encrypt(expectedwif,passphrase)
        if resultpriv == expectedpriv:
            print('Encryption Success!')
        else:
            print('Encryption Failed!')
            print('Expected %s' %(expectedpriv))
            print('Returned %s' %(resultpriv))
        decryptedpriv = bip38_decrypt(resultpriv,passphrase)
        if decryptedpriv == expectedwif:
            print('Decryption Success!')
        else:
            print('Decryption Failed!')
            print('Expected %s' %(expectedwif))
            print('Returned %s' %(decryptedpriv))
        print('-')*80
