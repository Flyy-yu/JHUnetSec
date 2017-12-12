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
        print(src)
        print(srcPort)
        print(dst)
        print(dstPort)
        d = PacketBaseType.Deserializer()
        d.update(demuxData)
        for pkt in d.nextPackets():
            print(pkt)


if __name__ == '__main__':
    eva = eavesdrop()
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    loop.call_soon(eva.start)
    loop.run_forever()
