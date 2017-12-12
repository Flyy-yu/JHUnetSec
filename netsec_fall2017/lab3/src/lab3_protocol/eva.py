from .lab3a import *



def connectionMade(self):
    pass


def demux(self, src, srcPort, dst, dstPort, demuxData):
    pass

# dmux data is ***RAW*** data on Playground.
eavesdrop = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(demux, "20174.*.*.*")
asyncio.get_event_loop().create_connection(lambda: eavesdrop, "192.168.200.240", "9090")
