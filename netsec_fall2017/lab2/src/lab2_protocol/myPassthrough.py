import time
from .MyProtocolTransport import *
import logging
import asyncio


# logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
# logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr


class PassThroughc1(StackingProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        higherTransport = StackingTransport(self.transport)
        self.higherProtocol().connection_made(higherTransport)

    def data_received(self, data):
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)


#
class PassThroughs1(StackingProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        higherTransport = StackingTransport(self.transport)
        self.higherProtocol().connection_made(higherTransport)

    def data_received(self, data):
        self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost(exc)


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

    def transmit(self):
        if time.time() - self.timeout_timer > 0.5:
            print("from client seq: " + str(self.info_list.sequenceNumber))
            print(self.info_list.init_seq + len(self.info_list.outBuffer))
            if self.info_list.sequenceNumber < self.info_list.init_seq + len(self.info_list.outBuffer):
                self.timeout_timer = time.time()
                self.higherTransport.sent_data()
            else:
                print("done,get me out xD from client")
        txDelay = 1
        asyncio.get_event_loop().call_later(txDelay, self.transmit)

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

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 1 and self.state == 0 and self.handshake == False:
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
                        # if pkt.Type == 3:
                        #     RIP_ACK = PEEPPacket()
                        #     RIP_ACK.Type = 4
                        #     RIP_ACK.calculateChecksum()
                        #     print("client: RIP-ACK sent")
                        #     self.transport.write(RIP_ACK.__serialize__())

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
                    if pkt.Type == 4:
                        # if verify_packet(pkt, self.expected_packet):
                        print("get ripx ack from server")
                    if pkt.Type == 3:
                        RIP_ACK = PEEPPacket()
                        RIP_ACK.Type = 4
                        RIP_ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        RIP_ACK.calculateChecksum()
                        print("client: RIPy-ACK sent")
                        self.transport.write(RIP_ACK.__serialize__())

    def connection_lost(self, exc):

        # Rip = PEEPPacket()
        # Rip.Type = 3  # ACK -  TYPE 2
        # self.seq = self.seq + 1
        # Rip.updateSeqAcknumber(seq=self.seq, ack=1)
        # print("client: ACK sent")
        # Rip.Checksum = Rip.calculateChecksum()
        # self.transport.write(Rip.__serialize__())
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

    def transmit(self):
        if time.time() - self.timeout_timer > 0.5:
            print("from server seq: " + str(self.info_list.sequenceNumber))
            print(self.info_list.init_seq + len(self.info_list.outBuffer))
            if self.info_list.sequenceNumber < self.info_list.init_seq + len(self.info_list.outBuffer):
                self.higherTransport.sent_data()
                self.timeout_timer = time.time()
            else:

                print("done,get me out xD from server")

        txDelay = 1
        asyncio.get_event_loop().call_later(txDelay, self.transmit)

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
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

                elif pkt.Type == 2 and self.state == 1 and self.handshake == False:
                    if pkt.verifyChecksum():
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
                        RIP_ACK = PEEPPacket()
                        RIP_ACK.Type = 4
                        RIP_ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        RIP_ACK.calculateChecksum()
                        print("server: RIPx-ACK sent")
                        self.transport.write(RIP_ACK.__serialize__())

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
