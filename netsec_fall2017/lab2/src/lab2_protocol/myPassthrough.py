import time
from .MyProtocolTransport import *
import logging

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
        self.higherProtocol().connection_lost()
        self.transport = None


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
        self.higherProtocol().connection_lost()
        self.transport = None


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
        self.sessid = ''
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0
        self.databuffer = ''
        self.info_list = item_list()

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
                        # self.sessid = pkt.SessionId
                        print("The session id is", self.sessid)
                        ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        print("client: ACK sent")
                        ACK.Checksum = ACK.calculateChecksum()
                        self.transport.write(ACK.__serialize__())
                        self.state = 1
                        self.handshake = True
                        print("ACK sent, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the self.info_list for this protocal
                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size

                        # setup stuff for data transfer
                        self.info_list.sequenceNumber = self.seq
                        # self.info_list.SessionId = self.sessid
                        self.info_list.init_seq = self.seq
                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(self.info_list)
                        self.higherProtocol().connection_made(self.higherTransport)

                        # if pkt.Type == 3:
                        #     RIP_ACK = PEEPPacket()
                        #     RIP_ACK.Type = 4
                        #     RIP_ACK.calculateChecksum()
                        #     print("client: RIP-ACK sent")
                        #     self.transport.write(RIP_ACK.__serialize__())

            # client and server should be the same, start from here
            if self.handshake:
                if pkt.Type == 5:
                    if verify_packet(pkt, self.sessid, self.expected_packet):
                        # print("verify_packet from server")
                        self.expected_packet = self.expected_packet + len(pkt.Data)
                        # print( "seq number:" + str(pkt.SequenceNumber))
                        Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data), self.sessid)
                        self.transport.write(Ackpacket.__serialize__())
                        self.higherProtocol().data_received(pkt.Data)

                if pkt.Type == 2:
                    if verify_ack(pkt, self.sessid):

                        self.ack_counter = self.ack_counter + 1
                        # print(self.ack_counter)
                        # print("I got an ACK")
                        # print(pkt.Acknowledgement)
                        # print("ack number:" + str(pkt.Acknowledgement))

                        if self.ack_counter == window_size and pkt.Acknowledgement < len(
                                self.info_list.file_data) + self.seq:
                            # print("next round")
                            self.ack_counter = 0
                            self.info_list.sequenceNumber = pkt.Acknowledgement
                            if pkt.Acknowledgement < self.info_list.init_seq + len(self.info_list.file_data):
                                self.higherTransport.write(self.info_list.file_data)

                        if pkt.Acknowledgement == len(self.info_list.file_data) + self.seq:
                            self.seq = pkt.Acknowledgement
                            self.ack_counter = 0
                            self.info_list.init_seq = self.seq
                            self.info_list.sequenceNumber = self.info_list.init_seq
                            self.higherTransport.setinfo(self.info_list)
                            # print("done")

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost()
        self.transport = None


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
        self.sessid = ''
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0
        self.info_list = item_list()

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
                        self.sessid = str(time.time())
                        # SYN_ACK.SessionId = self.sessid
                        self.seq = self.seq + 1
                        SYN_ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        SYN_ACK.Checksum = SYN_ACK.calculateChecksum()
                        print("server: SYN-ACK sent")
                        self.transport.write(SYN_ACK.__serialize__())
                        self.state = 1

                if pkt.Type == 2 and self.state == 1 and self.handshake == False:
                    if pkt.verifyChecksum():
                        self.handshake = True
                        print("got ACK, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the self.info_list for this protocal
                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size

                        # setup stuff for data transfer
                        self.info_list.sequenceNumber = self.seq
                        # self.info_list.SessionId = self.sessid
                        self.info_list.init_seq = self.seq

                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(self.info_list)
                        self.higherProtocol().connection_made(self.higherTransport)
                        break
                        # if pkt.Type == 3:
                        #     RIP_ACK = PEEPPacket()
                        #     RIP_ACK.Type = 4
                        #     RIP_ACK.calculateChecksum()
                        #     print("server: RIP-ACK sent")
                        #     self.transport.write(RIP_ACK.__serialize__())

            # client and server should be the same, start from here
            if self.handshake:
                if pkt.Type == 5:
                    if verify_packet(pkt, self.sessid, self.expected_packet):
                        # print("verify_packet from server")
                        self.expected_packet = self.expected_packet + len(pkt.Data)
                        Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data), self.sessid)
                        # print("seq number:" + str(pkt.SequenceNumber))
                        self.transport.write(Ackpacket.__serialize__())
                        self.higherProtocol().data_received(pkt.Data)

                if pkt.Type == 2:
                    self.ack_counter = self.ack_counter + 1
                    # print(self.ack_counter)
                    # print("I got an ACK")
                    # print("ack number:" + str(pkt.Acknowledgement))

                    if self.ack_counter == window_size and pkt.Acknowledgement <= len(
                            self.info_list.file_data) + self.seq:
                        # print("next round")
                        self.ack_counter = 0
                        self.info_list.sequenceNumber = pkt.Acknowledgement
                        if pkt.Acknowledgement < self.info_list.init_seq + len(self.info_list.file_data):
                            self.higherTransport.write(self.info_list.file_data)

                    if pkt.Acknowledgement == len(self.info_list.file_data) + self.seq:
                        self.seq = pkt.Acknowledgement
                        self.ack_counter = 0
                        self.info_list.init_seq = self.seq
                        self.info_list.sequenceNumber = self.info_list.init_seq
                        self.higherTransport.setinfo(self.info_list)
                        # print("done")

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost()
        self.transport = None


def verify_packet(packet, id, expected_packet):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    # if packet.SessionId != id:
    #     print("wrong session ID")
    #     goodpacket = False
    if expected_packet != packet.SequenceNumber:
        print("wrong packet seq number")
        goodpacket = False
    return goodpacket


def verify_ack(packet, id):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    # if packet.SessionId != id:
    #     print("wrong session ID")
    #     goodpacket = False
    return goodpacket


def generate_ACK(seq_number, ack_number, id):
    ACK = PEEPPacket()
    ACK.Type = 2
    ACK.SequenceNumber = seq_number
    ACK.Acknowledgement = ack_number
    # ACK.SessionId = id
    # print("this is my ack number " + str(ack_number))
    ACK.Checksum = ACK.calculateChecksum()

    return ACK




    # FIELDS = [
    #     ("Type", UINT8),
    #     ("SequenceNumber", UINT32({Optional: True})),
    #     ("Checksum", UINT16),
    #     ("SessionId", STRING({Optional: True})),
    #     ("Acknowledgement", UINT32({Optional: True})),
    #     ("Data", BUFFER({Optional: True}))
    # ]
    # # Create MyProtocolPackets
    #     for each pkt in MyProtocolPackets:
    #         self.lowerTransport().write(pkt.__serialize__())
