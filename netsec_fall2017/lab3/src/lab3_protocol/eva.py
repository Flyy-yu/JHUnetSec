from .lab3a import *


class eavesdrop(asyncio.Protocol):
    def connectionMade(self):
        pass


def demux(self, src, srcPort, dst, dstPort, demuxData):
    d = PacketBaseType.Deserializer()
    d.update(demuxData)
    for pkt in d.nextPackets():
        print(pkt)

    


eavesdrop = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(demux, "20174.*.*.*")
asyncio.get_event_loop().create_connection(lambda: eavesdrop, "192.168.200.240", "9090")

