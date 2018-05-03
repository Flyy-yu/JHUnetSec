import asyncio
import logging
import playground
from .mypacket import *
import translations

logging.getLogger().setLevel(logging.NOTSET)  # this logs *everything*
logging.getLogger().addHandler(logging.StreamHandler())  # logs to stderr


class eavesdrop(asyncio.Protocol):
    def __init__(self):
        self._discoveryConnection = playground.network.protocols.switching.PlaygroundSwitchTxProtocol(self,
                                                                                                      "20181.*.*.*")

        # self.translator = translations.NetworkTranslator()
        self.waitingMessage = None
        self.buffer = b""

    def start(self):
        coro = asyncio.get_event_loop().create_connection(lambda: self._discoveryConnection, "192.168.200.240", "9090")
        asyncio.get_event_loop().create_task(coro)

    def connectionMade(self):
        pass

    def pros(self, message):
        lines = message.split(b"\n")
        if len(lines) == 0:
            raise Exception("No Message")
        mType, msg, version = lines[0].split(b" ")

        headers = {}
        for line in lines[1:]:
            k, v = line.split(b":")
            headers[k.strip()] = v.strip()
        return mType, msg, headers

    def demux(self, src, srcPort, dst, dstPort, demuxData):
        print(src)
        print(srcPort)
        print(dst)
        print(dstPort)
        self.buffer += demuxData

        while True:
            if self.waitingMessage is None:
                if b"\n\n" in self.buffer:
                    index = self.buffer.index(b"\n\n")
                    message = self.buffer[:index]
                    self.buffer = self.buffer[index + 2:]
                    self.waitingMessage = self.pros(message)
                else:
                    return
            else:
                headerType, headerArg, headers = self.waitingMessage
                contentLength = int(headers.get(b"Content_length", "0"))
                if len(self.buffer) < contentLength:
                    return
                body, self.buffer = self.buffer[:contentLength], self.buffer[contentLength:]
                self.waitingMessage = None

                print(headerType)
                print(headerArg)
                print(headers)
                print(body)

if __name__ == '__main__':
    eva = eavesdrop()
    loop = asyncio.get_event_loop()
    loop.set_debug(enabled=True)
    loop.call_soon(eva.start)
    loop.run_forever()

