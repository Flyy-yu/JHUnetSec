from .lab3a import *

logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr


class eavesdrop(asyncio.Protocol):
    def __init__(self):
        self._discoveryConnection = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(self,
                                                                                                      "20174.*.*.*")

    def start(self):
        coro = asyncio.get_event_loop().create_connection(lambda: self._discoveryConnection, "192.168.200.240", "9090")
        asyncio.get_event_loop().create_task(coro)

    def connectionMade(self):
        pass

    def demux(self, src, srcPort, dst, dstPort, demuxData):
        if src == '20174.1.2333.2333':
            print(src)
            print(srcPort)
            print(dst)
            print(dstPort)
            d = PEEPPacket.Deserializer()
            d.update(demuxData)

            for pkt in d.nextPackets():
                print(pkt.DEFINITION_IDENTIFIER)
                print(pkt.SequenceNumber)
                print(pkt.Type)
                print(pkt.Data)


if __name__ == '__main__':
    eva = eavesdrop()
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    loop.call_soon(eva.start)
    loop.run_forever()
