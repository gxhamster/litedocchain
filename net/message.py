from typing import Self
from serialization.serialize import Serializable
from primitives.block import Block
from struct import Struct
from typing import Self
import hashlib

MAGIC_HDR_VALUE = b'litedocchain'

class MsgHdr(Serializable):
    """ Every message sent on the blockchain network will have a header
    with the metadata of the payload. Command field will be used to identify
    which type of msg packet.
    """
    struct = Struct('>12sHI4s')
    CHECKSUM_LEN = 4
    def __init__(self, command: int = 0) -> None:
        super().__init__()
        self.magic: bytes = MAGIC_HDR_VALUE # 12 bytes (char)
        self.command: int = command         # 02 bytes (short)
        self.size: int = 0                  # 04 bytes (int) Size of the payload. Bitcoin max=32MB
        self.checksum: bytes = b''          # 04 bytes (char) 4 byte sha256 of payload
            
    def Serialize(self) -> bytes:
        return self.struct.pack(self.magic, self.command, self.size, self.checksum)

    def Deserialize(self, buffer: bytes):
        m, c, s, ch  = self.struct.unpack(buffer)
        self.magic = m
        assert self.magic == MAGIC_HDR_VALUE
        self.command = c
        self.size = s
        self.checksum = ch
        return self

    def __repr__(self) -> str:
        return f"""MessageHeader(
    magic={self.magic},
    command={self.command},
    size={self.size},
    checksum={self.checksum})"""

class GetBlocksMsg(Serializable):
    struct = Struct('>32s32s')   
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(1)
        self.highestHash: bytes = b''  # 32 bytes
        self.stoppingHash: bytes = b'' # 32 bytes
    
    def Serialize(self) -> bytes:
        return self.hdr.Serialize() + self.struct.pack(self.highestHash, self.stoppingHash)
    
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
        checksum = hashlib.sha256(dataBuf).digest()[:MsgHdr.CHECKSUM_LEN]
        return checksum

    
    def __repr__(self) -> str:
        return f"""GetBlocksMsg(
    {self.hdr},
    highestHash={self.highestHash},
    stoppingHash={self.stoppingHash})"""

class BlockDataMsg(Serializable):
    struct = Block.struct
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(2)
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
        checksum = hashlib.sha256(dataBuf).digest()[:MsgHdr.CHECKSUM_LEN]
        return checksum
