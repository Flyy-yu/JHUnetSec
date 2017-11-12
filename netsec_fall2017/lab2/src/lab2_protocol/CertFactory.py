import os

from playground.common.CipherUtil import *
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

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
def main():
    # Loading a Certificate
    # rootCertificate = loadCertFromFile("root.crt")
    # Get issuer details
    # Returns a dictionary, parse it to get individual fields
    # rootCertificateIssuerDetails = getCertIssuer(rootCertificate)

    # Get subject details
    # Returns a dictionary, parse it to get individual fields
    # rootCertificateSubjectDetails = getCertSubject(rootCertificate)
    '''cert = x509.load_pem_x509_certificate(getCert(), default_backend())
    public_key = cert.public_key()
    print(isinstance(public_key, rsa.RSAPublicKey))'''


    cert = getCertFromBytes(getCert())
    public_key = cert.public_key()
    iv = os.urandom(16)
    print(isinstance(public_key, rsa.RSAPublicKey))
    print(getCertIssuer(cert))
    print(getCertSubject(cert))
    enc = CIPHER_AES128_CBC(public_key, iv)
    ciphertext = enc.encrypt("test message")
    print(ciphertext)



if __name__ == "__main__":
    main()





