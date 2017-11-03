import os
root = os.path.dirname(os.path.abspath(__file__))

def getPrivateKeyForAddr():
    # Enter the location of the Private key as per the location of the system
    with open(root + "/sign/user1_private")as fp:
        private_key_user = fp.read()
    fp.close()

    return private_key_user

def getCertForAddr():
    certs = []
    with open(root + "certs") as fp:
        certs.append(fp.read())
    fp.close()
    with open(root + "CAcerts") as fp:
        certs.append((fp.read()))
    fp.close()

    return certs

def getRootCert():

    with open(root + "rootCert") as fp:
        root_cert = fp.read()

    return root_cert


