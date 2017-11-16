import os
import codecs
import random
from playground.common.CipherUtil import *
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher.PKCS1_OAEP import PKCS1OAEP_Cipher
from Crypto import Random

from Crypto.Util import Counter
from Crypto.Signature import PKCS1_v1_5
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

def getClientCert():
    certs = []
    with open(path + "/certs/client.cert", "rb") as fp:
        certs.append(fp.read())
    fp.close()
    with open(path + "/certs/signed.cert", "rb") as fp:
        certs.append((fp.read()))
    fp.close()
    with open(path + "/certs/root.crt", "rb") as fp:
        certs.append((fp.read()))
    fp.close()
    print(type(certs[0]))
    return certs

def getServerCert():
    certs = []
    with open(path + "/certs/server.cert", "rb") as fp:
        certs.append(fp.read())
    fp.close()
    with open(path + "/certs/signed.cert", "rb") as fp:
        certs.append((fp.read()))
    fp.close()
    with open(path + "/certs/root.crt", "rb") as fp:
        certs.append((fp.read()))
    fp.close()
    return certs



def getClientKey():
    with open(path + "/certs/client.key") as fp:
        client_key = fp.read()
    fp.close()
    return client_key

def getServerKey():
    with open(path + "/certs/server.key") as fp:
        server_key = fp.read()
    fp.close()
    return server_key


#print(root)
#print(path)
#print(getPrivateKeyForAddr())
#print(getClientCert())
#print(getServerCert())

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
    Encrypter = PKCS1OAEP_Cipher(key, None, None, None)
    enc_data = Encrypter.encrypt(PKs)
    print(enc_data)
    print(type(enc_data))
    '''
    print(key.can_encrypt())
    print(key.can_sign())
    print(key.has_private())
    public_key = key.publickey()
    enc_data = public_key.encrypt(PKs,32)
    print("Enc: "+str(enc_data))
    print("Enc"+str(type(enc_data)))
    '''
    private_key = RSA.importKey(getPrivateKeyForAddr())
    print(private_key.has_private())
    Decrypter = PKCS1OAEP_Cipher(private_key, None, None, None)
    dec_data = Decrypter.decrypt(enc_data)
    print("Dec"+str(type(dec_data)))
    print("Dec: "+str(dec_data))

def main3():
    client_cert = getClientCert()
    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert[0])
    pubKey_client = crtObj.get_pubkey()
    p_clientstring = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKey_client)
    print(p_clientstring)
    p_client = RSA.importKey(p_clientstring)
    k_client = RSA.importKey(getClientKey())

    PKs = os.urandom(16)
    enc_data = p_client.encrypt(PKs, 32)
    print(len(enc_data))
    print(enc_data[0])
    print("Enc: " + str(enc_data))
    dec_data = k_client.decrypt(enc_data)
    print(dec_data[1])
    print("Dec: " + str(dec_data))
    assert PKs == dec_data
    print("Done")
    '''for i in range(len(certs) - 1):
        cert_obj = crypto.load_certificate(crypto.FILETYPE_PEM, certs[i])

    for i in range(len(cert_obj) - 1):
        issuer = cert_obj[i].get_issuer()'''
    # list = [getCertFromBytes(certs[0]), getCertFromBytes(certs[1]), getCertFromBytes(certs[2])]

def verify_certchain(certs):
    X509_list = []
    crypto_list = []
    for cert in certs:
        x509obj = x509.load_pem_x509_certificate(cert, default_backend())
        X509_list.append(x509obj)
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        crypto_list.append(cert)

    # verify the issuer and subject
    for i in range(len(crypto_list) - 1):
        issuer = crypto_list[i].get_issuer()
        print(issuer)
        subject = crypto_list[i + 1].get_subject()
        print(subject)
        if issuer == subject:
            print("issuer and subject verified")
        else:
            return False

    # verify the signature sha256
    for i in range(len(X509_list) - 1):
        this = X509_list[i]
        #print(this)
        #print(this.signature)
        sig = RSA_SIGNATURE_MAC(X509_list[i+1].public_key())
        #print(issuer)
        if not sig.verify(this.tbs_certificate_bytes, this.signature):
            return False
        else:
            print("signature verified")
    return True


def main4():
    certs = getClientCert()
    # print(verify_certchain(certs))
    for cert in certs:
        c_cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        subject = c_cert.get_subject()
        print("subject:"+str(subject))
        issued_to = subject.CN  # the Common Name field
        print("issued to: "+issued_to)
        issuer = c_cert.get_issuer()
        print("issuer:"+str(issuer))
        issued_by = issuer.CN
        print("issued by: "+issued_by)
        aa = c_cert.get_signature_algorithm()
        print(aa)
        print("-----------------------------")





if __name__ == "__main__":
    verify_certchain(getServerCert())
    #main3()




    # print("Done")
    #a = []
    #a = getClientCert()
    #print(verify_certchain(getClientCert()))
    # print(getServerCert())
    # cert_obj = []
    # certs = getClientCert()
    # for i in range(len(certs)):
    #     cert_obj.append(crypto.load_certificate(crypto.FILETYPE_PEM, certs[i]))
    #     print(certs[i])
    # cert_store = crypto.X509Store()
    # #cert_store.add_cert(cert_obj[0])
    # cert_store.add_cert(cert_obj[1])
    # cert_store.add_cert(cert_obj[2])
    # store_ctx = crypto.X509StoreContext(cert_store, cert_obj[0])
    # store_ctx.verify_certificate()

    # print(verify_certchain(getClientCert()))
    # Prepare X509 objects

# openssl x509 -req -days 360 -in <CSR-for-the-new-device> -CA <your-intermediate-CA-certificate> -CAkey <your-intermediate-CA-key> -out <your-new-certificate> -set_serial <a random number>
# openssl x509 -req -days 360 -in server.csr -CA signed.cert -CAkey private_key -out server.cert -set_serial 176
# openssl verify -CAfile RootCert.pem -untrusted Intermediate.pem UserCert.pem
# openssl verify -verbose -CAfile root.crt -untrusted server.cert signed.cert

# Country Name (2 letter code) [AU]:US
# State or Province Name (full name) [Some-State]:MD
# Locality Name (eg, city) []:Baltimore
# Organization Name (eg, company) [Internet Widgits Pty Ltd]:JHUNetworkSecurityFall2017
# Organizational Unit Name (eg, section) []:PETF
# Common Name (e.g. server FQDN or YOUR name) []:20174.1.n
# Email Address []:<Your email address>
# Challenge: <LEAVE BLANK>
# Company: <Your Name>
# python -m test.ThroughputTester [client or server] --reference-stack=lab2_protocol
# server 20174.1.6666.1  -set_serial 176
# client 20174.1.6666.2 -set_serial 41


    # os.system("openssl ca -config " + os.path.abspath("demoCA/openssl.cnf") + " " +
    #           "-keyfile intermediate.key -passin pass:" + intermediate_password + " " +
    #           "-cert intermediate.pem -extensions v3_req -notext -md sha256 -batch " +
    #           "-days " + str(days) + " -in server.csr -out server.pem")
