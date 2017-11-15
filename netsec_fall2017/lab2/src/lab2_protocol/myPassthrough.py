import time
import os
from .MyProtocolTransport import *
import logging
import asyncio
import hashlib
from .CertFactory import *
from Crypto.PublicKey import RSA
from playground.common.CipherUtil import *
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import HMAC, SHA256

logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

# M1, C->S:  PlsHello(Nc, [C_Certs])
# M2, S->C:  PlsHello(Ns, [S_Certs])
# M3, C->S:  PlsKeyExchange( {PKc}S_public, Ns+1 )
# M4, S->C:  PlsKeyExchange( {PKs}C_public, Nc+1 )
# M5, C->S:  PlsHandshakeDone( Sha1(M1, M2, M3, M4) )
# M6, S->C:  PlsHandshakeDone( Sha1(M1, M2, M3, M4) )


# State machine for client SL
# 0: intial state, send C → S: PlsHello(Nc, [C_Certs])
# 1: receive PlsHello, send C->S:  PlsKeyExchange( {PKc}S_public, Ns+1 )
# 2: receive PlsKeyExchange, send PlsHandshakeDone
# 3: receive PlsHandshakeDone, handshake done


class PassThroughc1(StackingProtocol):
    def __init__(self):
        self.transport = None
        self.handshake = False
        self.higherTransport = None
        self._deserializer = PacketBaseType.Deserializer()
        self.state = 0
        self.C_Nonce = 0
        self.S_Nonce = 0
        self.S_Certs = []
        self.C_Certs = getClientCert()
        self.PKc = os.urandom(16)
        self.PKs = b''
        self.C_crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.C_Certs[0])
        self.CPubK = self.C_crtObj.get_pubkey()
        self.C_pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, self.CPubK)
        self.C_privKey = getClientKey()

        self.hashresult = hashlib.sha1()
        self.shash = hashlib.sha1()
        self.block = []

    def connection_made(self, transport):
        print("SL connection made")
        self.transport = transport
        helloPkt = PlsHello()
        self.C_Nonce = random.getrandbits(64)
        print(self.C_Nonce)
        helloPkt.Nonce = self.C_Nonce
        #helloPkt.Certs = helloPkt.generateCerts()
        helloPkt.Certs = self.C_Certs
        self.hashresult.update(helloPkt.__serialize__())
        self.transport.write(helloPkt.__serialize__())
        print("client: PlsHello sent")
        #higherTransport = StackingTransport(self.transport)
        #self.higherProtocol().connection_made(higherTransport)


    def data_received(self, data):
        #self.higherProtocol().data_received(data)
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PlsHello) and self.state == 0:
                print("client: PlsHello received")
                self.hashresult.update(pkt.__serialize__())
                self.S_Nonce = pkt.Nonce
                self.S_Certs = pkt.Certs
                keyExchange = PlsKeyExchange()
                crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.S_Certs[0])
                pubKeyObject = crtObj.get_pubkey()
                pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
                key = RSA.importKey(pubKeyString)
                public_key = key.publickey()
                Encrypter = PKCS1OAEP_Cipher(key, None, None, None)
                cipher = Encrypter.encrypt(self.PKc)
                keyExchange.PreKey = cipher
                keyExchange.NoncePlusOne = self.S_Nonce + 1
                self.state = 1
                self.hashresult.update(keyExchange.__serialize__())
                self.transport.write(keyExchange.__serialize__())
            elif isinstance(pkt, PlsKeyExchange) and self.state == 1:
                self.hashresult.update(pkt.__serialize__())
                print("client: PlsKeyExchange received")
                #check nc
                if pkt.NoncePlusOne == self.C_Nonce + 1:
                    print("client: check NC+1")
                    CpriK = RSA.importKey(self.C_privKey)
                    Decrypter = PKCS1OAEP_Cipher(CpriK, None, None, None)
                    self.PKs = Decrypter.decrypt(pkt.PreKey)
                    hdshkdone = PlsHandshakeDone()
                    hdshkdone.ValidationHash = self.hashresult.digest()
                    self.state = 2
                    self.transport.write(hdshkdone.__serialize__())
                    print("client: send handshake done")
            elif isinstance(pkt, PlsHandshakeDone) and self.state == 2:
                # check hash
                if self.hashresult.digest() == pkt.ValidationHash:
                    print("-------------client: Hash Validated, PLS handshake done!-------------")
                    #self.higherTransport = StackingTransport
                    #higherTransport = StackingTransport(self.transport)
                    self.state = 3
                    self.handshake = True

                    print(str(self.C_Nonce).encode('utf-8') + str(self.S_Nonce).encode('utf-8') + str(self.PKc).encode('utf-8') + str(self.PKs).encode('utf-8'))
                    self.shash.update("PLS1.0".encode('utf-8') + str(self.C_Nonce).encode('utf-8') + str(self.S_Nonce).encode('utf-8') + str(self.PKc).encode('utf-8') + str(self.PKs).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_1
                    self.shash.update(str(self.block[0]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_2
                    self.shash.update(str(self.block[1]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_3
                    self.shash.update(str(self.block[2]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_4
                    self.shash.update(str(self.block[3]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    for blo in self.block:
                        print(blo)
                    self.block_bytes = hexlify(self.block[0] + self.block[1] + self.block[2] + self.block[3] + self.block[4])
                    print(len(self.block_bytes))
                    self.Ekc = self.block_bytes[0:32]
                    self.Eks = self.block_bytes[32:64]
                    self.IVc = self.block_bytes[64:96]
                    self.IVs = self.block_bytes[96:128]
                    self.MKc = self.block_bytes[128:160]
                    self.MKs = self.block_bytes[160:192]

                    self.higherTransport = PLSTransport(self.transport)
                    self.higherTransport.get_info(self.Ekc, self.IVc, self.MKc)
                    self.higherProtocol().connection_made(self.higherTransport)
                    print("client higher sent data")
                else:
                    print("Hash validated error!")
            elif isinstance(pkt, PlsData) and self.handshake:
                plaintext = self.decrypt(self.Eks, self.IVs, pkt.Ciphertext)
                hm1 = HMAC.new(self.MKs, digestmod=SHA256)
                hm1.update(pkt.Ciphertext)
                verifyMac = hm1.digest()
                if (verifyMac == pkt.Mac):
                    print("--------------Mac Verify---------------")
                self.higherProtocol().data_received(plaintext)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def decrypt(self, key, iv, ciphertext):
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





# State machine for server SL
# 0: initial state, wait for PlsHello
# 1: receive PlsHello, send PlsKeyExchange( {PKs}C_public, Nc+1 )
# 2: receive PlsKeyExchange, send PlsKeyExchange
# 3: receive PlsHandshakeDone, send PlsHandshakeDone, check hash value, handshake done
class PassThroughs1(StackingProtocol):
    def __init__(self):
        self.transport = None
        self.handshake = False
        self.higherTransport = None
        self._deserializer = PacketBaseType.Deserializer()
        self.state = 0
        self.C_Nonce = 0
        self.S_Nonce = 0
        self.S_Certs = getServerCert()
        self.C_Certs = []
        self.PKs = os.urandom(16)
        self.PKc = b''
        self.S_crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.S_Certs[0])
        self.SPubK = self.S_crtObj.get_pubkey()
        self.SPriK = getServerKey()
        self.S_pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, self.SPubK)
        self.hashresult = hashlib.sha1()
        self.shash = hashlib.sha1()
        self.block = []

    def connection_made(self, transport):
        print("SL connection made server")
        self.transport = transport

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PlsHello) and self.state == 0:
                self.hashresult.update(bytes(pkt.__serialize__()))
                self.C_Nonce = pkt.Nonce
                self.C_Certs = pkt.Certs
                helloPkt = PlsHello()
                self.S_Nonce = random.getrandbits(64)

                helloPkt.Nonce = self.S_Nonce
                helloPkt.Certs = self.S_Certs
                self.hashresult.update(bytes(helloPkt.__serialize__()))
                self.state = 1
                self.transport.write(helloPkt.__serialize__())
                print("server: PlsHello sent")
            elif isinstance(pkt, PlsKeyExchange) and self.state == 1:
                self.hashresult.update(bytes(pkt.__serialize__()))
                # check nc
                if pkt.NoncePlusOne == self.S_Nonce + 1:
                    print("server: check NC+1")
                    priK = RSA.importKey(self.SPriK)
                    Decrypter = PKCS1OAEP_Cipher(priK, None, None, None)
                    self.PKc = Decrypter.decrypt(pkt.PreKey)
                    keyExchange = PlsKeyExchange()
                    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.C_Certs[0])
                    pubKeyObject = crtObj.get_pubkey()
                    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
                    key = RSA.importKey(pubKeyString)
                    Encrypter = PKCS1OAEP_Cipher(key, None, None, None)
                    cipher = Encrypter.encrypt(self.PKs)
                    keyExchange.PreKey = cipher
                    keyExchange.NoncePlusOne = self.C_Nonce + 1
                    self.hashresult.update(bytes(keyExchange.__serialize__()))
                    self.state = 2
                    self.transport.write(keyExchange.__serialize__())
                else:
                    print("server: NC+1 error")
            elif isinstance(pkt, PlsHandshakeDone) and self.state == 2:
                hdshkdone = PlsHandshakeDone()
                hdshkdone.ValidationHash = self.hashresult.digest()
                print("server: Reveive handshake done")
                # check hash
                if self.hashresult.digest() == pkt.ValidationHash:
                    self.state = 3
                    self.handshake = True
                    print(str(self.C_Nonce).encode('utf-8') + str(self.S_Nonce).encode('utf-8') + str(self.PKc).encode('utf-8') + str(self.PKs).encode('utf-8'))
                    self.shash.update("PLS1.0".encode('utf-8') + str(self.C_Nonce).encode('utf-8') + str(self.S_Nonce).encode('utf-8') + str(self.PKc).encode('utf-8') + str(self.PKs).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_1
                    self.shash.update(str(self.block[0]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_2
                    self.shash.update(str(self.block[1]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_3
                    self.shash.update(str(self.block[2]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    # block_4
                    self.shash.update(str(self.block[3]).encode('utf-8'))
                    self.block.append(self.shash.digest())
                    for blo in self.block:
                        print(blo)
                    self.block_bytes = hexlify(
                        self.block[0] + self.block[1] + self.block[2] + self.block[3] + self.block[4])
                    print(len(self.block_bytes))
                    self.Ekc = self.block_bytes[0:32]
                    self.Eks = self.block_bytes[32:64]
                    self.IVc = self.block_bytes[64:96]
                    self.IVs = self.block_bytes[96:128]
                    self.MKc = self.block_bytes[128:160]
                    self.MKs = self.block_bytes[160:192]
                    self.transport.write(hdshkdone.__serialize__())
                    self.higherTransport = PLSTransport(self.transport)
                    self.higherTransport.get_info(self.Eks, self.IVs, self.MKs)
                    self.higherProtocol().connection_made(self.higherTransport)
                    print("-------------server: Hash Validated, PLS handshake done!-------------")
                else:
                    print("Hash validated error!")
            elif isinstance(pkt, PlsData) and self.handshake:
                plaintext = self.decrypt(self.Ekc, self.IVc, pkt.Ciphertext)
                hm1 = HMAC.new(self.MKc, digestmod=SHA256)
                hm1.update(pkt.Ciphertext)
                verifyMac = hm1.digest()
                if(verifyMac == pkt.Mac):
                    print("--------------Mac Verify---------------")
                self.higherProtocol().data_received(plaintext)




    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def decrypt(self, key, iv, ciphertext):
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



#


# state machine for client
# 0: initial state
# 1: SYN sent, wait for SYN-ACK
# 2: SYN-ACK received, sent ACK
class PassThroughc2(StackingProtocol):
    def __init__(self):
        self.transport = None
        self._deserializer = PEEPPacket.Deserializer()
        self.handshake = False
        self.seq = 0
        self.state = 0
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0
        self.databuffer = ''
        self.timeout_timer = time.time()
        self.info_list = item_list()
        self.higherTransport = None
        self.lastcorrect = 0
        self.lastAck = 0
        self.close_timer = time.time()
        self.forceclose = 0

    def transmit(self):
        if time.time() - self.timeout_timer > 0.5:
            if self.info_list.sequenceNumber < self.info_list.init_seq + len(self.info_list.outBuffer):
                if self.lastAck > self.info_list.sequenceNumber:
                    self.info_list.sequenceNumber = self.lastAck
                self.ack_counter = 0
                self.timeout_timer = time.time()
                self.higherTransport.sent_data()
            else:
                print("client waiting...to...end")

        if time.time() - self.close_timer > 5:
            self.forceclose += 1
            self.close_timer = time.time()
            Rip = PEEPPacket()
            Rip.Type = 3
            Rip.updateSeqAcknumber(self.info_list.sequenceNumber, ack=1)
            print("client: Rip sent")
            Rip.Checksum = Rip.calculateChecksum()
            self.transport.write(Rip.__serialize__())

            if self.forceclose > 5:
                self.info_list.readyToclose = True
                self.higherTransport.close()
                return

        txDelay = 1
        asyncio.get_event_loop().call_later(txDelay, self.transmit)

    def resentsyn(self, pkt):
        if self.state == 0:
            self.transport.write(pkt.__serialize__())
            asyncio.get_event_loop().call_later(1, self.resentsyn, pkt)

    def connection_made(self, transport):
        self.transport = transport
        SYN = PEEPPacket()
        SYN.SequenceNumber = self.seq
        self.seq = self.seq + 1
        SYN.Type = 0  # SYN - TYPE 0
        SYN.Checksum = SYN.calculateChecksum()
        print("client: SYN sent")
        SYNbyte = SYN.__serialize__()
        self.transport.write(SYNbyte)
        self.resentsyn(SYN)

    def data_received(self, data):
        self.close_timer = time.time()
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 1 and self.state == 0 and not self.handshake:
                    print("SYN-ACK received")
                    if pkt.verifyChecksum():
                        ACK = PEEPPacket()
                        ACK.Type = 2  # ACK -  TYPE 2
                        self.seq = self.seq + 1
                        ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        print("client: ACK sent")
                        ACK.Checksum = ACK.calculateChecksum()
                        self.transport.write(ACK.__serialize__())
                        self.state = 1

                        print("ACK sent, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the self.info_list for this protocal
                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size
                        # setup stuff for data transfer
                        self.info_list.sequenceNumber = self.seq
                        self.info_list.init_seq = self.seq
                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(self.info_list)
                        self.higherProtocol().connection_made(self.higherTransport)
                        self.handshake = True
                        self.transmit()


                        # client and server should be the same, start from here
                elif self.handshake:
                    if pkt.Type == 5:
                        if verify_packet(pkt, self.expected_packet):
                            # print("verify_packet from server")
                            self.lastcorrect = pkt.SequenceNumber + len(pkt.Data)
                            self.expected_packet = self.expected_packet + len(pkt.Data)
                            Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data))
                            # print("seq number:" + str(pkt.SequenceNumber))
                            self.transport.write(Ackpacket.__serialize__())
                            self.higherProtocol().data_received(pkt.Data)
                        else:

                            Ackpacket = generate_ACK(self.seq, self.lastcorrect)
                            # print("seq number:" + str(pkt.SequenceNumber))
                            print("the client ack number out last correct: " + str(self.lastcorrect))
                            self.transport.write(Ackpacket.__serialize__())

                    if pkt.Type == 2:
                        if verify_ack(pkt):
                            self.ack_counter = self.ack_counter + 1
                            # print(self.ack_counter)
                            # print("I got an ACK")
                            # print(pkt.Acknowledgement)
                            # print("ack number:" + str(pkt.Acknowledgement))

                            if self.info_list.sequenceNumber < pkt.Acknowledgement:
                                self.info_list.sequenceNumber = pkt.Acknowledgement
                                self.lastAck = pkt.Acknowledgement

                            if self.ack_counter == window_size and pkt.Acknowledgement < len(
                                    self.info_list.outBuffer) + self.seq:
                                self.timeout_timer = time.time()
                                print("next round")
                                # self.info_list.from_where = "passthough"
                                self.ack_counter = 0

                                if pkt.Acknowledgement < self.info_list.init_seq + len(self.info_list.outBuffer):
                                    self.higherTransport.sent_data()

                            elif pkt.Acknowledgement == len(self.info_list.outBuffer) + self.seq:
                                self.seq = pkt.Acknowledgement
                                self.ack_counter = 0
                                self.higherTransport.setinfo(self.info_list)
                                print("done")
                    # improve this at lab3
                    if pkt.Type == 4:
                        print("get rip ack from server,close transport")
                        self.info_list.readyToclose = True
                        self.higherTransport.close()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)


#
# state machine for server
# 0: initial state, wait for SYN
# 1: received SYN, sent SYN-ACK, wait for ACK
# 2: ACK received, finished handshake
class PassThroughs2(StackingProtocol):
    def __init__(self):
        self.transport = None
        self._deserializer = PEEPPacket.Deserializer()
        self.handshake = False
        self.seq = 0
        self.state = 0
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0
        self.info_list = item_list()
        self.timeout_timer = time.time()
        self.higherTransport = None
        self.lastcorrect = 0
        self.lastAck = 0
        self.close_timer = time.time()

    def transmit(self):
        if time.time() - self.timeout_timer > 0.5:
            if self.info_list.sequenceNumber < self.info_list.init_seq + len(self.info_list.outBuffer):
                if self.lastAck > self.info_list.sequenceNumber:
                    self.info_list.sequenceNumber = self.lastAck
                self.higherTransport.sent_data()
                self.timeout_timer = time.time()
                self.ack_counter = 0
            else:
                print("server waiting...for..RIP")
                if time.time() - self.close_timer > 30:
                    self.info_list.readyToclose = True
                    self.higherTransport.close()
                    return
        txDelay = 1
        asyncio.get_event_loop().call_later(txDelay, self.transmit)

    def connection_made(self, transport):
        self.transport = transport

    def resentsynack(self, pkt):
        if self.state == 1:
            self.transport.write(pkt.__serialize__())
            asyncio.get_event_loop().call_later(1, self.resentsynack, pkt)

    def data_received(self, data):
        self.close_timer = time.time()
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 0 and self.state == 0:
                    if pkt.verifyChecksum():
                        print("received SYN")
                        SYN_ACK = PEEPPacket()
                        SYN_ACK.Type = 1
                        self.seq = self.seq + 1
                        SYN_ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        SYN_ACK.Checksum = SYN_ACK.calculateChecksum()
                        print("server: SYN-ACK sent")
                        self.transport.write(SYN_ACK.__serialize__())
                        self.state = 1
                        self.resentsynack(SYN_ACK)

                elif pkt.Type == 2 and self.state == 1 and not self.handshake:
                    if pkt.verifyChecksum():
                        self.state = 3
                        print("got ACK, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the self.info_list for this protocal

                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size
                        # setup stuff for data transfer
                        self.info_list.sequenceNumber = self.seq
                        self.info_list.init_seq = self.seq

                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(self.info_list)
                        self.higherProtocol().connection_made(self.higherTransport)
                        self.handshake = True
                        self.transmit()
                        break


                        # client and server should be the same, start from here
                elif self.handshake:
                    if pkt.Type == 5:
                        if verify_packet(pkt, self.expected_packet):
                            # print("verify_packet from server")
                            self.lastcorrect = pkt.SequenceNumber + len(pkt.Data)
                            self.expected_packet = self.expected_packet + len(pkt.Data)
                            Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data))
                            # print("seq number:" + str(pkt.SequenceNumber))
                            self.transport.write(Ackpacket.__serialize__())
                            self.higherProtocol().data_received(pkt.Data)
                        else:
                            Ackpacket = generate_ACK(self.seq, self.lastcorrect)
                            # print("seq number:" + str(pkt.SequenceNumber))
                            print("the server ack number out last correct: " + str(self.lastcorrect))
                            self.transport.write(Ackpacket.__serialize__())

                    if pkt.Type == 2:
                        if verify_ack(pkt):
                            self.ack_counter = self.ack_counter + 1
                            # print(self.ack_counter)
                            # print("I got an ACK")
                            # print(pkt.Acknowledgement)
                            # print("ack number:" + str(pkt.Acknowledgement))

                            if self.info_list.sequenceNumber < pkt.Acknowledgement:
                                self.info_list.sequenceNumber = pkt.Acknowledgement
                                self.lastAck = pkt.Acknowledgement
                            if self.ack_counter == window_size and pkt.Acknowledgement < len(
                                    self.info_list.outBuffer) + self.seq:
                                self.timeout_timer = time.time()
                                print("next round")
                                # self.info_list.from_where = "passthough"
                                self.ack_counter = 0

                                if pkt.Acknowledgement < self.info_list.init_seq + len(self.info_list.outBuffer):
                                    self.higherTransport.sent_data()

                            elif pkt.Acknowledgement == len(self.info_list.outBuffer) + self.seq:
                                self.seq = pkt.Acknowledgement
                                self.ack_counter = 0
                                self.higherTransport.setinfo(self.info_list)
                                print("done")

                    if pkt.Type == 3:
                        if self.info_list.sequenceNumber >= self.info_list.init_seq + len(self.info_list.outBuffer):
                            RIP_ACK = PEEPPacket()
                            RIP_ACK.Type = 4
                            RIP_ACK.updateSeqAcknumber(seq=self.info_list.sequenceNumber, ack=pkt.Acknowledgement)
                            RIP_ACK.Checksum = RIP_ACK.calculateChecksum()
                            print("server: RIP-ACK sent, ready to close")
                            self.transport.write(RIP_ACK.__serialize__())
                            self.info_list.readyToclose = True
                            self.higherTransport.close()

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)


def verify_packet(packet, expected_packet):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    if expected_packet != packet.SequenceNumber:
        print("expect_number:" + str(expected_packet))
        print("packet number: " + str(packet.SequenceNumber))
        print("wrong packet seq number")
        goodpacket = False
    return goodpacket


def verify_ack(packet):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    return goodpacket


def generate_ACK(seq_number, ack_number):
    ACK = PEEPPacket()
    ACK.Type = 2
    ACK.SequenceNumber = seq_number
    ACK.Acknowledgement = ack_number
    # print("this is my ack number " + str(ack_number))
    ACK.Checksum = ACK.calculateChecksum()

    return ACK


    # FIELDS = [
    #     ("Type", UINT8),
    #     ("SequenceNumber", UINT32({Optional: True})),
    #     ("Checksum", UINT16),
    #     ("Acknowledgement", UINT32({Optional: True})),
    #     ("Data", BUFFER({Optional: True}))
    # ]
    # # Create MyProtocolPackets
    #     for each pkt in MyProtocolPackets:
    #         self.lowerTransport().write(pkt.__serialize__())

