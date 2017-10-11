import time
from MyProtocolTransport import *
import logging

# logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
# logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr

info_list = item_list()


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
        self._deserializer = PacketType.Deserializer()
        self.handshake = False
        self.seq = 0
        self.state = 0
        self.sessid = ''
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0

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
                if pkt.Type == 1 and self.state == 0:
                    print("SYN-ACK received")
                    if pkt.verifyChecksum():
                        ACK = PEEPPacket()
                        ACK.Type = 2  # ACK -  TYPE 2

                        self.seq = self.seq + 1
                        self.sessid = pkt.SessionId
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
                        # setup the info_list for this protocal
                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size

                        # setup stuff for data transfer
                        info_list.sequenceNumber = self.seq
                        info_list.SessionId = self.sessid
                        info_list.init_seq = self.seq
                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(info_list)
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
                        # print("verify_packet from client")
                        self.expected_packet = self.expected_packet + window_size
                        Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data), self.sessid)
                        self.higherProtocol().data_received(pkt.Data)
                        self.transport.write(Ackpacket.__serialize__())
                if pkt.Type == 2:
                    self.ack_counter = self.ack_counter + 1
                    # print(self.ack_counter)
                    # print("I got an ACK")
                    print(pkt.Acknowledgement)

                    if self.ack_counter == window_size and pkt.Acknowledgement <= len(info_list.file_data) + self.seq:
                        print("next round")
                        self.ack_counter = 0

                        w_p = (pkt.Acknowledgement - info_list.init_seq) / packet_size
                        print("this is wp: " + str(w_p))
                        info_list.w_p = int(w_p)
                        info_list.sequenceNumber = pkt.Acknowledgement
                        self.higherTransport.write(info_list.file_data)

                    if pkt.Acknowledgement == len(info_list.file_data) + self.seq:
                        self.seq = pkt.Acknowledgement
                        info_list.w_p = 0
                        self.ack_counter = 0
                        self.higherProtocol().data_received("Readyx#1")

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
        self._deserializer = PacketType.Deserializer()
        self.handshake = False
        self.seq = 0
        self.state = 0
        self.sessid = ''
        self.ack_counter = 0
        self.expected_packet = 0
        self.expected_ack = 0

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
                        SYN_ACK.SessionId = self.sessid
                        self.seq = self.seq + 1
                        SYN_ACK.updateSeqAcknumber(seq=self.seq, ack=pkt.SequenceNumber + 1)
                        SYN_ACK.Checksum = SYN_ACK.calculateChecksum()
                        print("server: SYN-ACK sent")
                        self.transport.write(SYN_ACK.__serialize__())
                        self.state = 1

                if pkt.Type == 2 and self.state == 1:
                    if pkt.verifyChecksum():
                        self.handshake = True
                        print("got ACK, handshake done")
                        print("------------------------------")
                        print("upper level start here")
                        # setup the info_list for this protocal
                        self.expected_packet = pkt.SequenceNumber
                        self.expected_ack = pkt.SequenceNumber + packet_size

                        # setup stuff for data transfer
                        info_list.sequenceNumber = self.seq
                        info_list.SessionId = self.sessid
                        info_list.init_seq = self.seq
                        self.higherTransport = MyTransport(self.transport)
                        self.higherTransport.setinfo(info_list)
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
                        self.expected_packet = self.expected_packet + packet_size
                        print(pkt.SequenceNumber)
                        Ackpacket = generate_ACK(self.seq, pkt.SequenceNumber + len(pkt.Data), self.sessid)
                        self.higherProtocol().data_received(pkt.Data)
                        self.transport.write(Ackpacket.__serialize__())
                if pkt.Type == 2:
                    self.ack_counter = self.ack_counter + 1
                    # print(self.ack_counter)
                    # print("I got an ACK")
                    print(pkt.Acknowledgement)

                    if self.ack_counter == window_size and pkt.Acknowledgement <= len(
                            info_list.file_data) + self.seq:
                        print("next round")
                        self.ack_counter = 0

                        w_p = (pkt.Acknowledgement - info_list.init_seq) / packet_size
                        print("this is wp: " + str(w_p))
                        info_list.w_p = int(w_p)
                        info_list.sequenceNumber = pkt.Acknowledgement
                        self.higherTransport.write(info_list.file_data)

                    if pkt.Acknowledgement == len(info_list.file_data) + self.seq:
                        self.seq = pkt.Acknowledgement
                        info_list.w_p = 0
                        self.ack_counter = 0
                        self.higherProtocol().data_received("Readyx#1")

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost()
        self.transport = None


def verify_packet(packet, id, expected_packet):
    goodpacket = True
    if packet.verifyChecksum() == False:
        print("wrong checksum")
        goodpacket = False
    if packet.SessionId != id:
        print("wrong session ID")
        goodpacket = False
    if window_size < (expected_packet - packet.SequenceNumber):
        print("wrong packet seq number")
        goodpacket = False

    return goodpacket


def generate_ACK(seq_number, ack_number, id):
    ACK = PEEPPacket()
    ACK.Type = 2
    ACK.SequenceNumber = seq_number
    ACK.Acknowledgement = ack_number
    ACK.SessionId = id
    # print("this is my ack number " + str(ack_number))
    ACK.calculateChecksum()
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
