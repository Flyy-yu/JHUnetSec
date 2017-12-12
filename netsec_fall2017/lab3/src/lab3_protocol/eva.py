from .lab3a import *


class eavesdrop(asyncio.Protocol):
    def __init__(self):
        pass
    
    def connectionMade(self):
        pass

    def demux(self, src, srcPort, dst, dstPort, demuxData):
        d = PacketBaseType.Deserializer()
        d.update(demuxData)
        for pkt in d.nextPackets():
            print(pkt)

    def start(self):
        self.eavesdrop = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(self.demux, "20174.*.*.*")
        coro = asyncio.get_event_loop().create_connection(lambda: self.eavesdrop, "192.168.200.240", "9090")
        loop = asyncio.get_event_loop()
        loop.run_until_complete(coro)
        loop.run_forever()
        loop.close()


if __name__ == '__main__':
    eva = eavesdrop()
    eva.start()
