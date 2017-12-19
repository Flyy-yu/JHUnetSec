import asyncio
import logging
import playground
from .mypacket import *

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
        d = PacketType.Deserializer()
        e = PacketType.Deserializer()
        d.update(demuxData)

        # class OpenSession(PacketType):
        #     DEFINITION_IDENTIFIER = "apps.bank.OpenSession"
        #     DEFINITION_VERSION = "1.0"
        #     FIELDS = [
        #         ("ClientNonce", UINT64),
        #         ("Login", STRING),
        #         ("PasswordHash", STRING)
        #     ]
        #
        # class SessionOpen(PacketType):
        #     DEFINITION_IDENTIFIER = "apps.bank.SessionOpen"
        #     DEFINITION_VERSION = "1.0"
        #     FIELDS = [
        #         ("ClientNonce", UINT64),
        #         ("ServerNonce", UINT64),
        #         ("Account", STRING)
        #     ]

        for pkt in d.nextPackets():
            if isinstance(pkt, PEEPPacket):
                e.update(pkt.Data)
                for pkt in e.nextPackets():
                    print("this packet is:" + pkt.DEFINITION_IDENTIFIER)
                    if (isinstance(pkt, SessionOpen)):
                        print("account:")
                        print(pkt.Account)
                    if (isinstance(pkt, OpenSession)):
                        print("login:")
                        print(pkt.Login)
                        print("passwordhash")
                        print(pkt.PasswordHash)

            if (isinstance(pkt, SessionOpen)):
                print("account:")
                print(pkt.Account)
            if (isinstance(pkt, OpenSession)):
                print("login:")
                print(pkt.Login)
                print("passwordhash")
                print(pkt.PasswordHash)


if __name__ == '__main__':
    eva = eavesdrop()
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    loop.call_soon(eva.start)
    loop.run_forever()
