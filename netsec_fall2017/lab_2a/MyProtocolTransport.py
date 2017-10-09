from playground.network.common import *
from mypacket import *


class item_list():
    sequenceNumber = 0
    SessionId = ''
    Acknowledgement = 0
    #packet_number = 0

class MyTransport(StackingTransport):

    def setinfo(self, info_list):
        self.info_list = info_list

    def write(self, data):  # this will be the data from the upper layer
        small_packet = PEEPPacket()
        for n in range(0, int(len(data) / 5) + 1):
            if (n + 1) * 5 < len(data):
                packet_data = data[n * 5: (n + 1) * 5]
            else:
                packet_data = data[n * 5:]
            small_packet.Type = 5  # data packet
            small_packet.Data = bytes(packet_data, 'utf-8')
            small_packet.SessionId = self.info_list.SessionId
            small_packet.SequenceNumber = self.info_list.sequenceNumber
            small_packet.Checksum = small_packet.calculateChecksum()
            self.lowerTransport().write(small_packet.__serialize__())
            # print("wow, this is the new write method")
