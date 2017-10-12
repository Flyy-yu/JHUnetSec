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
        print("my data length: "+str(len(data)))

        self.info_list.file_data = data
        small_packet = PEEPPacket()
        for n in range(0, window_size):
            front = self.info_list.sequenceNumber - self.info_list.init_seq

            if front + packet_size <= len(data):
                packet_data = data[front:front + packet_size]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
            else:
                packet_data = data[front:]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
                n = 999

            small_packet.Type = 5  # data packet
            small_packet.Data = packet_data
            small_packet.SessionId = self.info_list.SessionId
            small_packet.Checksum = small_packet.calculateChecksum()
            self.lowerTransport().write(small_packet.__serialize__())
            if n > window_size:
                break

    def get_data(self):
        return self.info_list.data
