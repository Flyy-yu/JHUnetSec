from playground.network.common import *
from .mypacket import *

packet_size = 10
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

    def write(self, data):  # this will be the data from the upper layer
        self.info_list.file_data = data
        small_packet = PEEPPacket()
        for n in range(0, window_size):
            # print("inwrite:")
            # print(self.info_list.sequenceNumber)
            # print(self.info_list.init_seq)
            front = self.info_list.sequenceNumber - self.info_list.init_seq
            #print("my front length: " + str(front))
            if front + packet_size <= len(data):
                #print("it should not be here")
                packet_data = data[front:front + packet_size]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
            else:
                packet_data = data[front:]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                n = 999

            small_packet.Type = 5  # data packet
            small_packet.Data = packet_data
            #small_packet.SessionId = self.info_list.SessionId
            small_packet.Checksum = small_packet.calculateChecksum()
            self.lowerTransport().write(small_packet.__serialize__())
            if n > window_size:
                break

    #


def get_data(self):
    return self.info_list.data
