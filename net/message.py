from typing import Self
from serialization.serialize import Serializable
from primitives.block import Block
from struct import Struct
from typing import Self
from enum import IntEnum
import hashlib

MAGIC_HDR_VALUE = b"litedocchain"

class MsgType(IntEnum):
    """Every MsgHdr has a command field which is a MsgType.
    Use this field to figure out what kind of message it is.
    """

    NOMSG = 0
    GETBLOCKMSG = 1
    BLOCKDATAMSG = 2


class MsgHdr(Serializable):
    """Every message sent on the blockchain network will have a header
    with the metadata of the payload. Command field will be used to identify
    which type of msg packet. Make sure to set the checksum and size of the payload in
    the hdr before sending the msg on the wire
    """

    struct = Struct(">12sHI4s")
    CHECKSUM_LEN = 4

    def __init__(self, command: MsgType = MsgType.NOMSG) -> None:
        super().__init__()
        self.magic: bytes = MAGIC_HDR_VALUE  # 12 bytes (char)
        self.command: MsgType = command  # 02 bytes (short)
        self.size: int = 0  # 04 bytes (int) Size of the payload. Bitcoin max=32MB
        self.checksum: bytes = b""  # 04 bytes (char) 4 byte sha256 of payload

    def Serialize(self) -> bytes:
        return self.struct.pack(self.magic, self.command, self.size, self.checksum)

    def Deserialize(self, buffer: bytes):
        m, c, s, ch = self.struct.unpack(buffer)
        self.magic = m
        assert self.magic == MAGIC_HDR_VALUE
        self.command = c
        self.size = s
        self.checksum = ch
        return self

    def __repr__(self) -> str:
        return f"""MsgHdr(magic={self.magic}, command={self.command}, size={self.size}, checksum={self.checksum})"""


class GetBlocksMsg(Serializable):
    struct = Struct(">32s32s")

    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(MsgType.GETBLOCKMSG)
        self.highestHash: bytes = b""   # 32 bytes
        self.stoppingHash: bytes = b""  # 32 bytes (zero to retreive to max limit)

    def Serialize(self) -> bytes:
        return self.hdr.Serialize() + self.struct.pack(
            self.highestHash, self.stoppingHash
        )

    def Deserialize(self, buffer: bytes):
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        h, s = self.struct.unpack(buffer[hdrSize:])
        self.highestHash = h
        self.stoppingHash = s
        return self

    def SetChecksumSize(self) -> None:
        self.hdr.checksum = self.CalculateChecksum()
        self.hdr.size = len(self.struct.pack(self.highestHash, self.stoppingHash))

    def CalculateChecksum(self) -> bytes:
        dataBuf = self.struct.pack(self.highestHash, self.stoppingHash)
        checksum = hashlib.sha256(dataBuf).digest()[: MsgHdr.CHECKSUM_LEN]
        return checksum

    def __repr__(self) -> str:
        return f"""GetBlocksMsg({self.hdr}, highestHash={self.highestHash}, stoppingHash={self.stoppingHash})"""


class BlockDataMsg(Serializable):
    struct = Block.struct

    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(MsgType.BLOCKDATAMSG)
        self.block: Block = Block()

    def Serialize(self) -> bytes:
        return self.hdr.Serialize() + self.block.Serialize()

    def Deserialize(self, buffer: bytes) -> Self:
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        self.block = self.block.Deserialize(buffer[hdrSize:])
        return self

    def CalculateChecksum(self) -> bytes:
        dataBuf = self.block.Serialize()
        checksum = hashlib.sha256(dataBuf).digest()[: MsgHdr.CHECKSUM_LEN]
        return checksum

    def __repr__(self) -> str:
        return f"BlockDataMsg(hdr={self.hdr}, block={self.block}"
