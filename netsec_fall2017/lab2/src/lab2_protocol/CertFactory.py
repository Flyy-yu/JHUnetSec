import os
import codecs
import random
from playground.common.CipherUtil import *
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.Util import Counter
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


key_bytes = 16

def encrypt(key, plaintext):
    print(len(key))
    assert len(key) == key_bytes

    # Choose a random, 16-byte IV.
    iv = random.new().read(AES.block_size)

    # Convert the IV to a Python integer.
    iv_int = int(binascii.hexlify(iv), 16)

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
    iv_int = int(iv.encode('hex'), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)

    # Create AES-CTR cipher.
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt and return the plaintext.
    plaintext = aes.decrypt(ciphertext)
    return plaintext




def main():
    # Loading a Certificate
    # rootCertificate = loadCertFromFile("root.crt")
    # Get issuer details
    # Returns a dictionary, parse it to get individual fields
    # rootCertificateIssuerDetails = getCertIssuer(rootCertificate)

    # Get subject details
    # Returns a dictionary, parse it to get individual fields
    # rootCertificateSubjectDetails = getCertSubject(rootCertificate)

    '''crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, getCert())
    pubKeyObject = crtObj.get_pubkey()
    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
    print(pubKeyString)'''

    Nc = random.getrandbits(64)
    Ns = random.getrandbits(64)
    PKc = random.getrandbits(128)
    PKs = random.getrandbits(128)
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
    block_bits = bin(int(block_bytes,16))
    print(len(block_bits))
    print(type(block_bits))
    print(block_bits)
    Ekc = block_bits[0:128]
    print(len(Ekc))
    print(Ekc)



    plaintext = "this is a text message"

    '''cert = getCertFromBytes(getCert())
    public_key = cert.public_key()
    iv = os.urandom(16)
    print(isinstance(public_key, rsa.RSAPublicKey))
    print(getCertIssuer(cert))
    print(getCertSubject(cert))
    zeroKey = "\x00" * 16  # 16 bytes of 0
    zeroIv = "\x00" * 16'''

    #(iv, ciphertext) = encrypt(pubKeyString, 'hella')
    #print(decrypt(pubKeyString, iv, ciphertext))






if __name__ == "__main__":
    main()




