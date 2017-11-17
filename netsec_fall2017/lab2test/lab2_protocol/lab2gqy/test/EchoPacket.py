from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import BOOL, STRING

class EchoPacket(PacketType):
    DEFINITION_IDENTIFIER = "test.EchoPacket"

    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("original", BOOL),
        ("message", STRING)
    ]
