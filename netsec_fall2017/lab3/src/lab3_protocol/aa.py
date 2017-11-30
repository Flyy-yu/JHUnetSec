import time
from .MyProtocolTransport import *
import logging
import asyncio
import hashlib
from .CertFactory import *
from Crypto.PublicKey import RSA
from playground.common.CipherUtil import *

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
        self.C_Certs = getCertForAddr()
        self.Pkc=os.urandom(16)
        self.Pks = [] #from server, used to generate keys
        self.C_crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.C_Certs[0])
        self.CPubK=self.C_crtObj.get_pubkey()
        self.C_pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, self.CPubK)
        self.C_privKey=getPrivateKeyForAddr()
        self.hashresult = hashlib.sha1()

    def connection_made(self, transport):
        print("SL connection made")
        self.transport = transport
        helloPkt = PlsHello()
        self.C_Nonce = random.getrandbits(64)
        print(self.C_Nonce)
        helloPkt.Nonce = self.C_Nonce
        # helloPkt.Certs = helloPkt.generateCerts()
        helloPkt.Certs = getCertForAddr()
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
                # print(key.can_encrypt())
                # print(key.can_sign())
                # print(key.has_private())
                public_key = key.publickey()
                cipher = public_key.encrypt(self.Pkc,32)
                print(self.Pkc)
                keyExchange.PreKey = cipher
                keyExchange.NoncePlusOne = self.S_Nonce + 1
                self.state = 1
                self.hashresult.update(keyExchange.__serialize__())
                self.transport.write(keyExchange.__serialize__())
                print("clinet: KeyEx sent")
            elif isinstance(pkt, PlsKeyExchange) and self.state == 1:
                self.hashresult.update(pkt.__serialize__())
                print("client: PlsKeyExchange received")
                #check nc
                if pkt.NoncePlusOne == self.C_Nonce + 1:
                    print("client: check NC+1")
                    CpriK=RSA.importKey(self.C_privKey)
                    self.Pks = CpriK.decrypt(pkt.PreKey)
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
                    self.higherTransport = PLSTransport(self.transport)
                    self.higherProtocol().connection_made(self.higherTransport)
                    print("client higher sent data")
                else:
                    print("Hash validated error!")
            elif isinstance(pkt, PlsData) and self.handshake:
                # plaintext = dec
                self.higherProtocol().data_received(pkt.Ciphertext)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)




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
        self.S_Certs = getCertForAddr()
        self.C_Certs = []
        self.Pks = os.urandom(16)
        self.S_crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.S_Certs[0])
        self.SPubK = self.S_crtObj.get_pubkey()
        self.SPriK=getPrivateKeyForAddr()
        self.S_pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, self.SPubK)
        self.hashresult = hashlib.sha1()

    def connection_made(self, transport):
        print("SL connection made server")
        self.transport = transport

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PlsHello) and self.state == 0:
                print("server: PlsHello received")
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
                    priK=RSA.importKey(self.SPriK)
                    self.Pkc=priK.decrypt(pkt.PreKey)
                    keyExchange = PlsKeyExchange()
                    crtObj = crypto.load_certificate(crypto.FILETYPE_PEM, self.C_Certs[0])
                    pubKeyObject = crtObj.get_pubkey()
                    pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, pubKeyObject)
                    key = RSA.importKey(pubKeyString)
                    public_key=key.publickey()
                    cipher=public_key.encrypt(self.Pks,32)
                    keyExchange.PreKey = cipher[0]
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
                    self.transport.write(hdshkdone.__serialize__())
                    self.higherTransport = PLSTransport(self.transport)
                    self.higherProtocol().connection_made(self.higherTransport)
                    print("-------------server: Hash Validated, PLS handshake done!-------------")
                else:
                    print("Hash validated error!")
            elif isinstance(pkt, PlsData) and self.handshake:
                # plaintext = dec
                self.higherProtocol().data_received(pkt.Ciphertext)



    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)

    def encrypto(self):
        enbytes = b''
        return enbytes

    def decrypto(self):
        debytes = b''
        return debytes



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

    # verify the CN
    print(X509_list[0].serial_number)
    print(X509_list[0].issuer)
    #print(len(cert.subject))
    print(X509_list[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value)
    print(X509_list[0].subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value)
    print(type(X509_list[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))
    address = X509_list[0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    print(address.startswith('20174.1.6666'))
    # verify the issuer and subject
    for i in range(len(crypto_list) - 1):
        issuer = crypto_list[i].get_issuer()
        # print(issuer)
        subject = crypto_list[i + 1].get_subject()
        # print(subject)
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
    #print(getCertForAddr())
    #print(getClientCert())




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
# openssl x509 -req -days 360 -in server.csr -CA signed.cert -CAkey private_key -out server.cert -set_serial 176 -sha256
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
# python -m test.ThroughputTester [client or server] --reference-stack=lab3_protocol
# server 20174.1.6666.1  -set_serial 176
# client 20174.1.6666.2 -set_serial 41

# cert info: openssl x509 -in server.cert -noout -text

    # os.system("openssl ca -config " + os.path.abspath("demoCA/openssl.cnf") + " " +
    #           "-keyfile intermediate.key -passin pass:" + intermediate_password + " " +
    #           "-cert intermediate.pem -extensions v3_req -notext -md sha256 -batch " +
    #           "-days " + str(days) + " -in server.csr -out server.pem")

# print("Received a connection from {}".format(self.transport.get_extra_info("peername")))
# print("Received a connection address {}".format(self.transport.get_extra_info("peername")[0]))
# print("Received a connection sock {}".format(self.transport.get_extra_info("sockname")))
# print("Received a connection host {}".format(self.transport.get_extra_info("hostname")))







#print(root)
#print(path)
#print(getPrivateKeyForAddr())
#print(getClientCert())
#print(getServerCert())

#the key length is 128bits
# key_bytes = 32
#
# def encrypt(key,iv, plaintext):
#     print(len(key))
#     assert len(key) == key_bytes
#
#     # Choose a random, 16-byte IV.
#
#     # Convert the IV to a Python integer.
#     iv_int = int(iv, 16)
#
#     # Create a new Counter object with IV = iv_int.
#     ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
#
#     # Create AES-CTR cipher.
#     aes = AES.new(key, AES.MODE_CTR, counter=ctr)
#
#     # Encrypt and return IV and ciphertext.
#     ciphertext = aes.encrypt(plaintext)
#     return (iv, ciphertext)
#
# # Takes as input a 32-byte key, a 16-byte IV, and a ciphertext, and outputs the
# # corresponding plaintext.
# def decrypt(key, iv, ciphertext):
#     assert len(key) == key_bytes
#
#     # Initialize counter for decryption. iv should be the same as the output of
#     # encrypt().
#     iv_int = int(iv, 16)
#     ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
#
#     # Create AES-CTR cipher.
#     aes = AES.new(key, AES.MODE_CTR, counter=ctr)
#
#     # Decrypt and return the plaintext.
#     plaintext = aes.decrypt(ciphertext)
#     return plaintext
