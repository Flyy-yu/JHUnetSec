from OpenSSL import crypto

def verify():
    with open('./server.cert', 'r') as cert_file:
        cert = cert_file.read()

    with open('./signed.cert', 'r') as int_cert_file:
        int_cert = int_cert_file.read()

    with open('./root.crt', 'r') as root_cert_file:
        root_cert = root_cert_file .read()

    trusted_certs = (int_cert, root_cert)
    verified = verify_chain_of_trust(cert, trusted_certs)

    if verified:
        print('Certificate verified')


def verify_chain_of_trust(cert_pem, trusted_cert_pems):

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    # Create and fill a X509Sore with trusted certs
    store = crypto.X509Store()
    for trusted_cert_pem in trusted_cert_pems:
        trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
        store.add_cert(trusted_cert)
    # store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pems[1]))
    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)
    # Returns None if certificate can be validated
    result = store_ctx.verify_certificate()

    if result is None:
        return True
    else:
        return False

if __name__ == "__main__":
    verify()