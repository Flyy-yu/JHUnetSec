import asyncio, sys, logging
import playground
from playground.network.common import StackingProtocol

from .EchoPacket import EchoPacket
# logging.getLogger().setLevel(logging.NOTSET)
# logging.getLogger().addHandler(logging.StreamHandler())

class EchoClientProtocol(StackingProtocol):
    """
    This is our class for the Client's protocol. It provides an interface
    for sending a message. When it receives a response, it prints it out.
    """

    def __init__(self, callback=None):
        super(EchoClientProtocol, self).__init__()
        self.buffer = ""
        if callback:
            self.callback = callback
        else:
            self.callback = print
        self.transport = None
        self.deserializer = EchoPacket.Deserializer()

    def close(self):
        self.__sendMessageActual("__QUIT__")

    def connection_made(self, transport):
        print("Connected to {}".format(transport.get_extra_info("peername")))
        self.transport = transport

    def data_received(self, data):
        self.deserializer.update(data)
        for echoPacket in self.deserializer.nextPackets():
            if echoPacket.original == False:
                self.callback(echoPacket.message)
            else:
                print("Got a message from server marked as original. Dropping.")

    def send(self, data):
        echoPacket = EchoPacket(original=True, message=data)

        self.transport.write(echoPacket.__serialize__())


class EchoControl:
    def __init__(self):
        self.txProtocol = None

    def buildProtocol(self):
        return EchoClientProtocol(self.callback)

    def connect(self, txProtocol):
        self.txProtocol = txProtocol
        print("Echo Connection to Server Established!")
        self.txProtocol = txProtocol
        sys.stdout.write("Enter Message: ")
        sys.stdout.flush()
        asyncio.get_event_loop().add_reader(sys.stdin, self.stdinAlert)

    def callback(self, message):
        print("Server Response: {}".format(message))
        sys.stdout.write("\nEnter Message: ")
        sys.stdout.flush()

    def stdinAlert(self):
        data = sys.stdin.readline()
        if data and data[-1] == "\n":
            data = data[:-1]  # strip off \n
        self.txProtocol.send(data)


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    # loop.set_debug(enabled=True)
    control = EchoControl()
    coro = playground.getConnector('lab2_protocol').create_playground_connection(control.buildProtocol, '26.1.22.9', 101)
    transport, protocol = loop.run_until_complete(coro)
    print("Echo Client Connected. Starting UI t:{}. p:{}".format(transport, protocol))
    control.connect(protocol)
    loop.run_forever()
