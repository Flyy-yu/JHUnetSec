from playground.network.common import *
from mypacket import *


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
class PassThroughc2(StackingProtocol):
    def __init__(self):
        self.transport = None
        self._deserializer = PacketType.Deserializer()
        self.handshake = False


    def connection_made(self, transport):
        self.transport = transport
        SYN = PEEPPacket()
        SYN.Type = 0
        SYN.Checksum = 1
        print("client: SYN sent")
        SYNbyte = SYN.__serialize__()
        self.transport.write(SYNbyte)


    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 1:
                    print("SYN-ACK received")
                    ACK = PEEPPacket()
                    ACK.Type = 2
                    ACK.Checksum = 1
                    print("client: ACK sent")
                    self.transport.write(ACK.__serialize__())
                    self.handshake = True
                    print("ACK sent, handshake done")
                    print("------------------------------")
                    print("upper level start here")
                    if self.handshake == True:
                        higherTransport = StackingTransport(self.transport)
                        self.higherProtocol().connection_made(higherTransport)

                # if pkt.Type == 3:
                #     RIP_ACK = PEEPPacket()
                #     RIP_ACK.Type = 4
                #     RIP_ACK.Checksum = 1
                #     print("client: RIP-ACK sent")
                #     self.transport.write(RIP_ACK.__serialize__())
        if self.handshake == True:
            self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost()
        self.transport = None


#
class PassThroughs2(StackingProtocol):
    def __init__(self):
        self.transport = None
        self._deserializer = PacketType.Deserializer()
        self.handshake = False

    def connection_made(self, transport):
        self.transport = transport


    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, PEEPPacket):
                if pkt.Type == 0:
                    print("received SYN")
                    SYN_ACK = PEEPPacket()
                    SYN_ACK.Type = 1
                    SYN_ACK.Checksum = 1
                    print("server: SYN-ACK sent")
                    self.transport.write(SYN_ACK.__serialize__())

                if pkt.Type == 2:
                    self.handshake = True
                    print("got ACK, handshake done")
                    print("------------------------------")
                    print("upper level start here")
                    higherTransport = StackingTransport(self.transport)
                    self.higherProtocol().connection_made(higherTransport)

                # if pkt.Type == 3:
                #     RIP_ACK = PEEPPacket()
                #     RIP_ACK.Type = 4
                #     RIP_ACK.Checksum = 1
                #     print("server: RIP-ACK sent")
                #     self.transport.write(RIP_ACK.__serialize__())

        if self.handshake == True:
            self.higherProtocol().data_received(data)

    def connection_lost(self, exc):
        self.higherProtocol().connection_lost()
        self.transport = None


#