from playground.network.common import *
from mypacket import *

packet_size = 5
window_size = 3


class item_list():
    sequenceNumber = 0
    SessionId = ''
    Acknowledgement = 0
    init_seq = 0
    file_data = ''
    w_p = 0


class MyTransport(StackingTransport):
    def setinfo(self, info_list):
        self.info_list = info_list

        # self.info_list.w_p->which packet to sent, the packet number

    def new_file(self):
        self.info_list.w_p = 0

    def write(self, data):  # this will be the data from the upper layer

        if self.info_list.w_p < 5:
            self.info_list.file_data = data

        small_packet = PEEPPacket()
        for n in range(0, window_size):
            temp = self.info_list.w_p + n
            if (self.info_list.w_p + 1) * packet_size < len(data):
                packet_data = data[temp * packet_size:(temp + 1) * packet_size]
                small_packet.SequenceNumber = self.info_list.sequenceNumber + n * packet_size
            else:
                packet_data = data[temp * packet_size:]
                small_packet.SequenceNumber = self.info_list.sequenceNumber + n * packet_size
                n = 999
                self.info_list.init_seq += self.info_list.sequenceNumber + (len(data) - temp * packet_size)
                self.info_list.sequenceNumber = self.info_list.init_seq
            small_packet.Type = 5  # data packet
            small_packet.Data = bytes(packet_data, 'utf-8')
            small_packet.SessionId = self.info_list.SessionId
            small_packet.Checksum = small_packet.calculateChecksum()
            self.lowerTransport().write(small_packet.__serialize__())
            if n > window_size:
                break

    def get_data(self):
        return self.info_list.data
