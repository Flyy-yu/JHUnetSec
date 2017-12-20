import os

root = os.path.dirname(os.path.abspath(__file__))
path = os.path.dirname(os.path.dirname(root))


def getPrivateKeyForAddr(addr):
    if addr == "20174.1.2333.1":
        with open(path + "/certs/server.key") as fp:
            server_key = fp.read()
        fp.close()
        return server_key
    if addr == "20174.1.2333.2":
        with open(path + "/certs/client.key") as fp:
            client_key = fp.read()
        fp.close()
        return client_key
    if addr == "20174.1.2333.2333":
        with open(path + "/certs/prikey2333") as fp:
            client_key = fp.read()
        fp.close()
        return client_key

    return None


def getCertsForAddr(addr):
    certs = []
    if addr == "20174.1.2333.1":
        with open(path + "/certs/server.cert", "rb") as fp:
            certs.append(fp.read())
        fp.close()
        with open(path + "/certs/signed.cert", "rb") as fp:
            certs.append((fp.read()))
        fp.close()
        return certs
    if addr == "20174.1.2333.2":
        with open(path + "/certs/client.cert", "rb") as fp:
            certs.append(fp.read())
        fp.close()
        with open(path + "/certs/signed.cert", "rb") as fp:
            certs.append((fp.read()))
        fp.close()
        return certs
    if addr == "20174.1.2333.2333":
        with open(path + "/certs/client2333.cert", "rb") as fp:
            certs.append(fp.read())
        fp.close()
        with open(path + "/certs/addr2333.cert", "rb") as fp:
            certs.append((fp.read()))
        fp.close()
        return certs
    if addr == "20174.1.1337.3":
        with open(path + "/certs/client636.cert", "rb") as fp:
            certs.append(fp.read())
        fp.close()
        with open(path + "/certs/addr636.cert", "rb") as fp:
            certs.append((fp.read()))
        fp.close()
        return certs
    return None


def getRootCert():
    with open(path + "/certs/root.crt", "rb") as fp:
        cert = fp.read()
    fp.close()
    return cert



    # import os
    #
    # root = os.path.dirname(os.path.abspath(__file__))
    # path = os.path.dirname(os.path.dirname(root))
    #
    #
    # def getPrivateKeyForAddr(addr):
    #     with open(path + "/certs/server.key") as fp:
    #         server_key = fp.read()
    #     fp.close()
    #     return server_key
    #
    #
    # def getCertsForAddr(addr):
    #     certs = []
    #
    #     with open(path + "/certs/server.cert", "rb") as fp:
    #         certs.append(fp.read())
    #     fp.close()
    #     with open(path + "/certs/signed.cert", "rb") as fp:
    #         certs.append((fp.read()))
    #     fp.close()
    #     return certs
    #
    #
    # def getRootCert():
    #     with open(path + "/certs/root.crt", "rb") as fp:
    #         cert = fp.read()
    #     fp.close()
    #     return cert