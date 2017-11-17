# We will use "BOOL1" and "STRING" in our message definition
import asyncio, logging
import playground

from .EchoPacket import EchoPacket
from playground.network.common import StackingProtocol
# MessageDefinition is the base class of all automatically serializable messages

# logger = logging.getLogger(__name__)

# logging.getLogger().setLevel(logging.NOTSET)
# logging.getLogger().addHandler(logging.StreamHandler())

class EchoServerProtocol(StackingProtocol):
    def __init__(self):
        super(EchoServerProtocol, self).__init__()
        self.deserializer = EchoPacket.Deserializer()
        self.transport = None

    def connection_made(self, transport):
        print("Received a connection from {}".format(transport.get_extra_info("peername")))
        self.transport = transport

    def connection_lost(self, reason=None):
        print("Lost connection to client. Cleaning up.")

    def data_received(self, data):
        self.deserializer.update(data)
        for echoPacket in self.deserializer.nextPackets():
            if echoPacket.original:
                print("Got {} from client.".format(echoPacket.message))

                if echoPacket.message == "__QUIT__":
                    print("Client instructed server to quit. Terminating")
                    self.transport.close()
                    return

                responsePacket = EchoPacket()
                responsePacket.original = False  # To prevent potentially infinte loops?
                responsePacket.message = echoPacket.message

                self.transport.write(responsePacket.__serialize__())

            else:
                print("Got a packet from client not marked as 'original'. Dropping")


if __name__ == "__main__":

    loop = asyncio.get_event_loop()
    # loop.set_debug(enabled=True)

    coro = playground.getConnector('lab2_protocol').create_playground_server(lambda: EchoServerProtocol(), 101)
    server = loop.run_until_complete(coro)
    print("Echo Server Started at {}".format(server.sockets[0].gethostname()))
    loop.run_forever()
