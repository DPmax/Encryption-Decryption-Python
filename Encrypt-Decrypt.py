# -*- coding: utf-8 -*-
"""
@author: LONGCHENG
"""

#Encrypt-Decrypt
"""
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
import hmac,hashlib
"""

from os import urandom
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as oaep
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
import requests
from datetime import datetime

def encrypt(message,public_key):
    key1 = urandom(16)
    iv = urandom(16)
    key2 = urandom(16)
    backend = default_backend()
    # Convert string to bytes
    bytemessage = bytes(message,'utf-8') 
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(bytemessage) + padder.finalize()
    cipher = Cipher(algorithms.AES(key1), modes.CBC(iv), backend = backend)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    h = HMAC(key2,hashes.SHA256(),backend=backend)
    h.update(ciphertext)
    tag = h.finalize()
    #print('\n')
    #print(tag)
    key3 = key1+ key2
    
    cipher2 = public_key.encrypt(
            key3,
            oaep.OAEP(
                    mgf = oaep.MGF1(algorithm = hashes.SHA1()),
                    algorithm = hashes.SHA1(),
                    label = None
            )
    )
    return cipher2, tag, ciphertext, iv

def decrypt(tag,private_key,cipher2, ciphertext, iv):
    backend = default_backend()
    key3 = private_key.decrypt(
            cipher2,
            oaep.OAEP(
                    mgf = oaep.MGF1(algorithm = hashes.SHA1()),
                    algorithm = hashes.SHA1(),
                    label = None
            )
    )
    
    key1 = key3[:16]
    key2 = key3[16:]
    
    
    h = HMAC(key2, hashes.SHA256(), backend=backend)
    h.update(ciphertext)
    tag2 = h.finalize()
    
    if tag != tag2:
        print("Wrong")

    decryptor = Cipher(algorithms.AES(key1), modes.CBC(iv), backend = backend).decryptor()
    plaintext_padded = decryptor.update(ciphertext)
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded = unpadder.update(plaintext_padded)
    unpadded += unpadder.finalize()
    plaintext = unpadded.decode('utf-8')
    return plaintext
    
    
def login():
    URL = 'https://berylliumtech.xyz/login'
    
    Username = input('Enter the username: ')
    Userpassword = input('Enter the Password: ')
    payload = {
            'username': Username,
            'userpassword': Userpassword,
            }
    session = requests.session()
    r = requests.post(URL, data = payload)
    return Username

    
def receive(username,message):
    print('1. Message from ', 'Longcheng')
    print('2. Message from ', 'Tom')
    print('0. Return ')
    choice = input(' \nEnter choice: ')
    if choice == '1':
        print('User Longcheng sent you: \n',message ,' at 2017-12-07 11:29:22')
    elif choice == '2':
        print('')
    else:
        accountinfo(username)
    accountinfo('Roberto')
    
def send(username):
    name = input('Type username for sending: ')
    message = input('Type message: ')
    # Generate key
    private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size = 2048,
            backend=default_backend()
        )

    public_key = private_key.public_key()

    cipher2, tag, cipher1, iv = encrypt(message, public_key)
    received = decrypt(tag, private_key, cipher2, cipher1, iv)
    receive('Longcheng',received)
    print(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print('\nMessage sending complete')
    accountinfo(username)

def logout():
    print('Bye.....')
    return 0
    
def accountinfo(username):
    print('\n\nHello', username)
    print(' 1. Receive Box')
    print(' 2. Send message')
    print(' 3. log out')
    choice = input(' \nEnter choice: ')
    if choice == '1':
        receive(username)
    elif choice == '2':
        send(username)
    elif choice == '3':
        logout()
    else:
        accountinfo(username)

"""
def encrypt(message,key1,key2,iv):
    # Convert string type text to byte type text
    byteMessage = bytes(message,'utf-8')
    # Padding to make message is multiple of 16 bytes
    # pkcs7 is the padding style
    # PKCS #7 is specified quite reasonably clearly in what amounts to a footnote in an RFC. 
    # You may find Wikipedia's description a bit easier to read.
    padded = pad(byteMessage,AES.block_size,style='pkcs7')
    # AES encryption using mode CBC
    encryptor = AES.new(key1,AES.MODE_CBC,iv)
    cipher = encryptor.encrypt(padded)
    tag = hmac.new(key2,cipher,hashlib.sha256).digest()
    print('\n')
    print(tag)
    return tag,cipher

def decrypt(iv,tag,key2,cipher,key1):
    
    # Check if has same tag
    tag2 = hmac.new(key2,cipher,hashlib.sha256).digest()
    print('\n')
    print(tag2)
    if tag != tag2:
        return ("Wrong tag")
    # If true
    # AES decryption using mode CBC
    decryptor = AES.new(key1,AES.MODE_CBC,iv)
    padded = decryptor.decrypt(cipher)
    # unpadding the bytemessage
    byteMessage = unpad(padded,AES.block_size, style='pkcs7')
    # convert bytemessage to string message
    plaintext = byteMessage.decode('utf-8')
    print('\n'+plaintext)

message = 'This is plain text'
# key1 for encryption
key1 = Random.get_random_bytes(16)
# initialization vector for AES
iv = Random.get_random_bytes(16)
# key2 for HMAC
key2 = Random.get_random_bytes(16)
tag,cipher = encrypt(message,key1,key2,iv)
decrypt(iv,tag,key2,cipher,key1)
"""



print('Welcome to End to End chat!')
print('\nPlease Log in ...\n')
userinfo = login()
accountinfo(userinfo)




"""
# Write key to disk for safe keeping
with open("path/to/store/key.pem","wb")as f:
    f.write(key.private_bytes(
            endcoding = serialization.Encoding.PEM,
            format = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.BestAvailableEncryption(),
    ))
    
# Load key
with open("path/to/key.pem","rb")as key_file:
    private_key = serialization.load_pem_private_key(
            key_file.read(),
            password = None,
            backend = default_backend()
    )
"""






