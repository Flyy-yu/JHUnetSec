from .lab3a import *


class eavesdrop(asyncio.Protocol):
    def __init__(self):

        self._discoveryConnection = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(self,
                                                                                                      "20174.*.*.*")

    def start(self):
        if self._running: return
        self._running = True
        coro = asyncio.get_event_loop().create_connection(lambda: self._discoveryConnection, "192.168.200.240", 9090)
        asyncio.get_event_loop().create_task(coro)

    def connectionMade(self):
        pass

    def demux(self, src, srcPort, dst, dstPort, demuxData):

        d = PacketType.Deserializer()
        d.update(demuxData)
        pkts = list(d.nextPackets())
        if not pkts: return
        self._discoveryConnection.write(dst, dstPort, src, srcPort)


if __name__ == '__main__':
    eva = eavesdrop()
    eva.start()
