import os
import codecs
import random
from playground.common.CipherUtil import *
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto import Random

from Crypto.Util import Counter
from Crypto.Hash import HMAC, SHA256
import binascii
import hashlib
from binascii import a2b_hex, b2a_hex, hexlify
from OpenSSL import crypto
from binascii import a2b_hex, b2a_hex
import base64

root = os.path.dirname(os.path.abspath(__file__))
path = os.path.dirname(os.path.dirname(root))

def getPrivateKeyForAddr():
    # Enter the location of the Private key as per the location of the system
    with open(path + "/certs/private_key")as fp:
        private_key_user = fp.read()
    fp.close()

    return private_key_user

def getCertForAddr():
    certs = []
    with open(path + "/certs/signed.cert") as fp:
        certs.append(fp.read())
    fp.close()
    with open(path + "/certs/csr_file") as fp:
        certs.append((fp.read()))
    fp.close()

    return certs

def getCert():
    with open(path + "/certs/signed.cert", "rb") as fp:
        cert = fp.read()

    return cert


def getRootCert():

    with open(path + "/certs/root.crt") as fp:
        root_cert = fp.read()

    return root_cert

#print(root)
#print(path)
#print(getPrivateKeyForAddr())

#the key length is 128bits
key_bytes = 32

def encrypt(key,iv, plaintext):
    print(len(key))
    assert len(key) == key_bytes

    # Choose a random, 16-byte IV.

    # Convert the IV to a Python integer.
    iv_int = int(iv, 16)

    # Create a new Counter object with IV = iv_int.
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Encrypt and return IV and ciphertext.
    ciphertext = aes.encrypt(plaintext)
    return (iv, ciphertext)

# Takes as input a 32-byte key, a 16-byte IV, and a ciphertext, and outputs the
# corresponding plaintext.
def decrypt(key, iv, ciphertext):
    assert len(key) == key_bytes

    # Initialize counter for decryption. iv should be the same as the output of
    # encrypt().
    iv_int = int(iv, 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt and return the plaintext.
    plaintext = aes.decrypt(ciphertext)
    return plaintext



#test for aes
def main1():
    # Loading a Certificate
    # rootCertificate = loadCertFromFile("root.crt")
    # Get issuer details
    # Returns a dictionary, parse it to get individual fields
    # rootCertificateIssuerDetails = getCertIssuer(rootCertificate)

    # Get subject details
    # Returns a dictionary, parse it to get individual fields
    # rootCertificateSubjectDetails = getCertSubject(rootCertificate)

    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, getCert())
    pubKeyObject = crtObj.get_pubkey()
    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    print(pubKeyString)

    Nc = random.getrandbits(64)
    Ns = random.getrandbits(64)
    PKc = random.getrandbits(128)
    PKs = random.getrandbits(128)
    print(type(PKc))
    print(PKc)
    shash = hashlib.sha1()
    block = []
    #block_0
    shash.update("PLS1.0".encode('utf-8') + str(Nc).encode('utf-8') + str(Ns).encode('utf-8') + str(PKc).encode('utf-8') + str(PKs).encode('utf-8'))
    block.append(shash.digest())
    #block_1
    shash.update(str(block[0]).encode('utf-8'))
    block.append(shash.digest())
    # block_2
    shash.update(str(block[1]).encode('utf-8'))
    block.append(shash.digest())
    # block_3
    shash.update(str(block[2]).encode('utf-8'))
    block.append(shash.digest())
    # block_4
    shash.update(str(block[3]).encode('utf-8'))
    block.append(shash.digest())
    for bl in block:
        print(bl)

    block_bytes = hexlify(block[0] + block[1] + block[2] + block[3] + block[4])
    print(len(block_bytes))
    '''block_bits = bin(int(block_bytes,base=16))
    print(len(block_bits))
    print(type(block_bits))
    print(block_bits)'''
    Ekc = block_bytes[0:32]
    Eks = block_bytes[32:64]
    IVc = block_bytes[64:96]
    IVs = block_bytes[96:128]
    MKc = block_bytes[128:160]
    MKs = block_bytes[160:192]

    #client enc(Ekc,IVc) Mac(Mkc)
    plaintext = "this is a text message"
    (iv, ciphertext) = encrypt(Ekc, IVc, plaintext)
    hm1 = HMAC.new(MKc, digestmod=SHA256)
    hm1.update(ciphertext)
    print("Mac: " + str(hm1.digest()))
    print("Dec: " + str(decrypt(Ekc, iv, ciphertext)))


#test for rsa
def main2():
    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, getCert())
    pubKeyObject = crtObj.get_pubkey()
    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    print(pubKeyString)
    PKs = os.urandom(16)
    print("PKs: "+str(PKs))
    print(type(PKs))
    key = RSA.importKey(pubKeyString)
    print(key.can_encrypt())
    print(key.can_sign())
    print(key.has_private())
    public_key = key.publickey()
    enc_data = public_key.encrypt(PKs,32)
    print("Enc: "+str(enc_data))

    private_key = RSA.importKey(getPrivateKeyForAddr())
    print(private_key.has_private())
    dec_data = private_key.decrypt(enc_data)
    print("Dec: "+str(dec_data))


if __name__ == "__main__":
    main2()




