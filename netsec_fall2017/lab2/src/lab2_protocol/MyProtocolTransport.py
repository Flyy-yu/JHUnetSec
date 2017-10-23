from playground.network.common import *
from .mypacket import *

packet_size = 1000
window_size = 3


class item_list():
    sequenceNumber = 0
    SessionId = ''
    Acknowledgement = 0
    init_seq = 0
    outBuffer = b''


class MyTransport(StackingTransport):
    def setinfo(self, info_list):
        self.info_list = info_list

    def write(self, data):  # this will be the data from the upper layer
        if len(self.info_list.outBuffer) < 3:
            self.info_list.init_seq = self.info_list.sequenceNumber

        if self.info_list.sequenceNumber == self.info_list.init_seq + len(self.info_list.outBuffer):
            self.info_list.outBuffer += data
            self.sent_data()
        else:
            self.info_list.outBuffer += data

            #

    def write_eof(self):
        pass

    def sent_data(self):
        # print(len(self.info_list.outBuffer))
        # print(self.info_list.sequenceNumber)
        small_packet = PEEPPacket()
        recordSeq = self.info_list.sequenceNumber
        for n in range(0, 3):
            place_to_send = self.info_list.sequenceNumber - self.info_list.init_seq

            # print("inwrite:")
            # print(self.info_list.sequenceNumber)
            # print(self.info_list.init_seq)
            # print("my front length: " + str(front))
            if place_to_send + packet_size <= len(self.info_list.outBuffer):
                # print("it should not be here")
                packet_data = self.info_list.outBuffer[place_to_send:place_to_send + packet_size]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
            else:

                packet_data = self.info_list.outBuffer[place_to_send:]
                small_packet.SequenceNumber = self.info_list.sequenceNumber
                self.info_list.sequenceNumber += len(packet_data)
                n = 999

            small_packet.Type = 5  # data packet
            small_packet.Data = packet_data
            # small_packet.SessionId = self.info_list.SessionId
            small_packet.Checksum = small_packet.calculateChecksum()
            print("i try to write sth")
            print(self.lowerTransport().is_closing())
            self.lowerTransport().write(small_packet.__serialize__())

            if n > window_size:
                break
        self.info_list.sequenceNumber = recordSeq


    def get_data(self):
        return self.info_list.data
