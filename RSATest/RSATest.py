import rsa
from base64 import b64encode, b64decode
from Crypto import Random

# Message will be a secret key for AES
msg1 = "Hello teamMates, I am the key!"
#rand = Random.get_random_bytes(8)

#msg2 = "Hello teamMates, I am okay!"
keysize = 2048
(public, private) = rsa.newkeys(keysize)
encrypted = b64encode(rsa.encrypt(msg1.encode(), private))
decrypted = rsa.decrypt(b64decode(encrypted), private)
signature = b64encode(rsa.sign(msg1.encode(), private))
verify = rsa.verify(msg1.encode(), b64decode(signature), public)

print(private.exportKey('PEM'))
print(public.exportKey('PEM'))
print("Encrypted: " + encrypted.decode())
print("Decrypted: '%s'" % decrypted)
print("Signature: " + signature.decode())
print("Verify: %s" % verify)
#rsa.verify(msg2.encode(), b64decode(signature), public)