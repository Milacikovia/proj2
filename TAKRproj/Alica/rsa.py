from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto import Random
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

def genNonce():
    return RNG.new().read(AES.block_size)

def genKey():
    return RNG.new().read(32)   # AES-256

def padData(data):
    if len(data) % 16 == 0:
        return data
    padRequired = 15 - (len(data) % 16)
    data = '%s\x80' % data
    data = '%s%s' % (data, '\x00' * padRequired)
    
    return data

def unpadData(data):
    if not data:
        return data
    data = data.rstrip('\x00')
    if data[-1] == '\x80':
        return data[:-1]
    else:
        return data

def encryptAES(data, key):
    data = pad_data(data)
    iV = RNG.new().read(AES.block_size)
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
    return unpad_data(data)

def newkeys(keysize):
    random_generator = Random.new().read
    key = RSA.generate(keysize, random_generator)
    private, public = key, key.publickey()
    return public, private

"""
def importKey(externKey):
    return RSA.importKey(externKey)

def getpublickey(priv_key):
    return priv_key.publickey()
"""

def encrypt(message, pub_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(message)

def decrypt(ciphertext, priv_key):
    #RSA encryption protocol according to PKCS#1 OAEP
    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(ciphertext)

def sign(message, priv_key):
    signer = PKCS1_v1_5.new(priv_key)
    digest = SHA256.new()   # hash = "SHA-256"
    digest.update(message)
    return signer.sign(digest)

def verify(message, signature, pub_key):
    signer = PKCS1_v1_5.new(pub_key)
    digest = SHA256.new()   # hash = "SHA-256"
    digest.update(message)
    return signer.verify(digest, signature)