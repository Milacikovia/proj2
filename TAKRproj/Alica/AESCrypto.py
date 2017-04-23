from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
#from Crypto.Random.OSRNG import posix as RNG
import os

def genNonce():
    return os.urandom(AES.block_size)

def genKey():
    return os.urandom(32)   # AES-256

def padData(data):
    if len(data) % 16 == 0:
        return data
    padRequired = 16 - (len(data) % 16)
    #print("Pridavam " + str(padRequired) + " HEX dat")
    data = '%s%s' % (data, '{' * padRequired)
    return data

def unpadData(data):
    if not data:
        return data
    data = data.rstrip('{'.encode())
    return data

def encrypt(data, key):
    data = padData(data)
    iV = genNonce()
    aes = AES.new(key, AES.MODE_CBC, iV)
    cipherText = aes.encrypt(data)
    return iV + cipherText

def decrypt(cipherText, key):
    """
    Decrypt a ciphertext encrypted with AES in CBC mode; assumes the IV
    has been prepended to the ciphertext.
    """
    if len(cipherText) <= AES.block_size:
        raise Exception("Invalid ciphertext.")
    iV = cipherText[:AES.block_size]
    cipherText = cipherText[AES.block_size:]
    aes = AES.new(key, AES.MODE_CBC, iV)
    data = aes.decrypt(cipherText)
    return unpadData(data)