import asyncio
from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, BUFFER, BOOL
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream
from playground.network.testing import MockTransportToProtocol
import random


class RequestToConnect(PacketType):
    DEFINITION_IDENTIFIER = "RequestToConnect"
    DEFINITION_VERSION = "1.0"


class NameRequest(PacketType):
    DEFINITION_IDENTIFIER = "NameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ID", UINT32),
        ("question", STRING)
    ]


class AnswerNameRequest(PacketType):
    DEFINITION_IDENTIFIER = "AnswerNameRequest"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("ID", UINT32),
        ("name", STRING)
    ]


class Result(PacketType):
    DEFINITION_IDENTIFIER = "result"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("result", BOOL)
    ]


# this is the client
class MyProtocolClient(asyncio.Protocol):
    def __init__(self, name, loop):
        self.name = name
        self.loop = loop
        self.transport = None
        self._deserializer = PacketType.Deserializer()

    def connection_made(self, transport):
        self.transport = transport
        requestPkt = RequestToConnect()
        requestpktB = requestPkt.__serialize__()
        print("client: RequestToConnect sent")
        transport.write(requestpktB)

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, NameRequest):
                sentNamePkt = AnswerNameRequest()
                sentNamePkt.ID = pkt.ID
                sentNamePkt.name = self.name
                sentNamePktB = sentNamePkt.__serialize__()
                print("client: AnswerNameRequest sent")
                self.transport.write(sentNamePktB)
            if isinstance(pkt, Result):
                if pkt.result == True:
                    print("connect to server success")
                elif pkt.result == False:
                    print("connect to server Failed")

    def connection_lost(self, exc):
        self.transport = None


# this is the server
class MyProtocolServer(asyncio.Protocol):
    def __init__(self):
        self.ConnectionDict = {}
        self.transport = None
        self._deserializer = PacketType.Deserializer()

    def connection_made(self, transport):
        self.transport = transport

    def data_received(self, data):
        self._deserializer.update(data)
        for pkt in self._deserializer.nextPackets():
            if isinstance(pkt, RequestToConnect):
                print(pkt.DEFINITION_IDENTIFIER)
                NameRequestpkt = NameRequest()
                outID = random.randint(100000, 999999)
                self.ConnectionDict[outID] = ""
                NameRequestpkt.ID = outID
                NameRequestpkt.question = "What's your name"
                NameRequestpktB = NameRequestpkt.__serialize__()
                print("server: NameRequestpkt sent")
                self.transport.write(NameRequestpktB)

            if isinstance(pkt, AnswerNameRequest):
                Resultpkt = Result()
                if pkt.ID in self.ConnectionDict:
                    self.ConnectionDict[pkt.ID] = pkt.name
                    Resultpkt.result = True
                    print("server: answer from valid user")
                else:
                    Resultpkt.result = False
                    print("server: u try to hack me?")
                ResultpktB = Resultpkt.__serialize__()
                print("server: Resultpkt sent")
                self.transport.write(ResultpktB)

    def connection_lost(self, exc):
        self.transport = None


#
def basicUnitTest():
    asyncio.set_event_loop(TestLoopEx())
    asyncio.set_event_loop(TestLoopEx())

    client = MyProtocolClient("hello", TestLoopEx())
    server = MyProtocolServer()
    transportToClient = MockTransportToProtocol(client)
    transportToServer = MockTransportToProtocol(server)
    server.connection_made(transportToClient)
    client.connection_made(transportToServer)


if __name__ == "__main__":
    basicUnitTest()
