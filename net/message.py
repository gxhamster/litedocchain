from typing import Self
from serialization.serialize import Serializable
from primitives.block import Block, BlockHeader
from struct import Struct, pack, unpack
from typing import Self
from enum import IntEnum
import hashlib

MAGIC_HDR_VALUE = b'litedocchain'

class MsgType(IntEnum):
    """Every MsgHdr has a command field which is a MsgType.
    Use this field to figure out what kind of message it is.
    """

    NOMSG = 0
    GETBLOCKMSG = 1
    BLOCKDATAMSG = 2
    INVMSG = 3
    VERSION = 4
    ACK = 5
    REQVERIFICATION = 6

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


class InvMsg(Serializable):
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(MsgType.INVMSG)
        self.blockCount: int = 0        # 4 byte (int)
        self.blocks: list[Block] = []   # Varies
        
    def Serialize(self) -> bytes:
        buffer = bytearray()
        buffer.extend(pack('>I', self.blockCount))
        for block in self.blocks:
            buffer.extend(block.Serialize())
        self.hdr.checksum =  hashlib.sha256(buffer).digest()[: MsgHdr.CHECKSUM_LEN]
        self.hdr.size = len(buffer)
        return self.hdr.Serialize() + bytes(buffer)
        
    def Deserialize(self, buffer: bytes) -> Self:
        self.blocks.clear()
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        
        blockCount, = unpack('>I', buffer[hdrSize:hdrSize+4])
        self.blockCount = blockCount
        blockBuf = buffer[hdrSize+4:]
        blockSize = BlockHeader.struct.size + Block.struct.size
        for i in range(blockCount):
            start = i * blockSize
            end = start + blockSize
            buf = blockBuf[start:end]
            block = Block()
            block.Deserialize(buf)
            self.blocks.append(block)
        return self
    
    def __repr__(self) -> str:
        return f"InvMsg(hdr={self.hdr}, blockCount={self.blockCount}, blocks={self.blocks})"
    

class VersionConnType(IntEnum):
    UNKNOWN = 0
    CLIENT = 1  
    NODE = 2

class VersionMsg(Serializable):
    """ A version packet is exchanged with node/client or node/peer
    whenever a connection is made. Helps to distinguish what kind of connection
    we are making.
    """
    struct = Struct('>B4sI')
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(MsgType.VERSION)
        self.connType: VersionConnType = VersionConnType.UNKNOWN # 1 byte 
        self.connAddr: bytes = b'' # 4 byte Convert string addresses using socket.inet_aton
        self.connPort: int = 0  # 4 byte (int)
        
    def Serialize(self) -> bytes:
        fields = self.struct.pack(self.connType, self.connAddr, self.connPort)
        self.hdr.checksum = hashlib.sha256(fields).digest()[: MsgHdr.CHECKSUM_LEN]
        self.hdr.size = len(fields)
        return self.hdr.Serialize() + fields
    
    def Deserialize(self, buffer: bytes) -> Self:
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        type, addr, port = self.struct.unpack(buffer[hdrSize:])
        self.connType = type
        self.connAddr = addr
        self.connPort = port
        return self
    
    def __repr__(self) -> str:
        return f"VersionMsg(hdr={self.hdr}, type={self.connType}, addr={self.connAddr}, port={self.connPort})"
        
class AckMsg(Serializable):
    struct = Struct('>I')
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(MsgType.ACK)
        self.status: int = 0 # To just pass any value with the ACK msg (if needed)
    
    def Serialize(self) -> bytes:
        fields = self.struct.pack(self.status)
        self.hdr.checksum = hashlib.sha256(fields).digest()[: MsgHdr.CHECKSUM_LEN]
        self.hdr.size = len(fields)
        return self.hdr.Serialize() + fields
    
    def Deserialize(self, buffer: bytes) -> Self:
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        nonce, = self.struct.unpack(buffer[hdrSize:])
        self.status = nonce
        return self
    
class ReqVerificationMsg(Serializable):
    """ Message sent by client to verify a file
    """
    struct = Struct(">32s32s")
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MsgHdr = MsgHdr(MsgType.REQVERIFICATION)
        self.file_hash: bytes = b'' # 32 byte
        self.pubkey: bytes = b''    # 32 byte
        
    def Serialize(self) -> bytes:
        fieldBytes = self.struct.pack(self.file_hash, self.pubkey)
        self.hdr.checksum = hashlib.sha256(fieldBytes).digest()[: MsgHdr.CHECKSUM_LEN]
        self.hdr.size = len(fieldBytes)
        hdrBytes = self.hdr.Serialize()
        return hdrBytes + fieldBytes

    
    def Deserialize(self, buffer: bytes) -> Self:
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        fHash, pKey = self.struct.unpack(buffer[hdrSize:])
        self.file_hash, self.pubkey = fHash, pKey
        return self
    
    def __repr__(self) -> str:
        return f"""{self.__class__.__name__}({self.hdr}, file_hash={self.file_hash.hex()}, pubkey={self.pubkey.hex()})"""
    
         
