from playground.network.common import *
from mypacket import *


class MyTransport(StackingTransport):
    def write(self, data):  # this will be the data from the upper layer

        small_packet = PEEPPacket()
        for n in range(0, int(len(data) / 2048)+1):
            if (n + 1) * 2048 < len(data):
                packet_data = data[n * 2048, (n + 1) * 2048]
            else:
                packet_data = data

            small_packet.Type = 5  # data packet
            small_packet.Data = bytes(packet_data, 'utf-8')
            small_packet.SessionId = "123"
            small_packet.SequenceNumber = 123
            small_packet.Checksum = small_packet.calculateChecksum()
            self.lowerTransport().write(small_packet.__serialize__())
            print("wow, this is the new write method")

