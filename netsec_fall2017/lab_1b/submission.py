from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL

class RequestToConnect(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.student.RequestToConnect"
    DEFINITION_VERSION = "1.0"


class NameRequest(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.student.NameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ID", UINT32),
        ("Question", STRING)
    ]


class AnswerNameRequest(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.student_x.AnswerNameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ID", UINT32),
        ("Answer", STRING)
    ]


class Result(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.student_x.result"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("result", STRING)
    ]


def basicUnitTest():


    packet1 = RequestToConnect()
    packet1Bytes = packet1.__serialize__()
    packet1a = RequestToConnect.Deserialize(packet1Bytes)
    assert packet1 == packet1a
    packet2 = NameRequest()
    packet2.Question = "What is your name?"
    packet2.ID = 1
    packet2Bytes = packet2.__serialize__()
    packet2a = NameRequest.Deserialize(packet2Bytes)
    assert packet2 == packet2a

    packet3 = AnswerNameRequest()
    packet3.Answer = "My name is Hello world"
    packet3.ID = 1
    packet3Bytes = packet3.__serialize__()
    packet3a = AnswerNameRequest.Deserialize(packet3Bytes)
    assert packet3 == packet3a

    packet4 = Result()
    packet4.result = "pass"
    packet4Bytes = packet4.__serialize__()
    packet4a = Result.Deserialize(packet4Bytes)
    assert packet4 == packet4a

if __name__ == "__main__":
    basicUnitTest()
