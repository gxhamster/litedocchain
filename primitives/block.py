import hashlib
from typing import Self
from struct import Struct
from serialization.serialize import Serializable

VERSION=1

class BlockHeader(Serializable):
  struct = Struct('>Bd32s32sI')
  def __init__(self):
    self.SetNull()

  def SetNull(self):
    super().__init__()
    self.version = 0                  # 1 byte char
    self.time: float = 0              # 8 byte double
    self.hashPrevBlock: bytes = b''   # 32 byte string
    self.hash: bytes = b''            # 32 byte string
    self.nonce: int = 0               # 4 byte integer

  def Serialize(self) -> bytes:
    return self.struct.pack(self.version, self.time, self.hashPrevBlock, self.hash, self.nonce)
  
  def Deserialize(self, buffer: bytes) -> Self:
    v, t, hp, h, n = self.struct.unpack(buffer)
    self.version = v
    self.time = t
    self.hashPrevBlock = hp
    self.hash = h
    self.nonce = n
    return self
  
  # Calculate the hash for all the block contents
  def CalculateHash(self, blockData: bytes=b'') -> bytes:
    buffer = bytearray()
    packStructNoHash = Struct('>Bd32sI')
    packedBytes = packStructNoHash.pack(self.version, self.time, self.hashPrevBlock, self.nonce)
    buffer.extend(packedBytes)
    if blockData != b'':
      buffer.extend(blockData)
    return hashlib.sha256(buffer).digest()
  
  def __repr__(self):
     return f"""BlockHeader(version={self.version},
  time={self.time},
  prev={self.hashPrevBlock},
  hash={self.hash}, 
  nonce={self.nonce})"""

class Block(Serializable):
  """ For simplicty in this project, we will consider one document
  to be in a seperate block. This blockchain will have no concept of
  transactions where multiple documents are combined into a single block.
  This would have increase storage requirements of each node in the future.
  The mining frequency will also might overload the network in the future.
  """
  struct = Struct('>64s')
  def __init__(self) -> None:
    super().__init__()
    self.hdr = BlockHeader()
    self.signature: bytes = b''   # Ed25519 produce 64 byte signature
  
  def Serialize(self) -> bytes:
    hdrBytes = self.hdr.Serialize()
    fieldBytes = self.struct.pack(self.signature)
    return hdrBytes + fieldBytes
  
  def Deserialize(self, buffer: bytes) -> Self:
    hdrSize = self.hdr.struct.size
    self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
    sigBytes, = self.struct.unpack(buffer[hdrSize:])
    self.signature = sigBytes
    return self
  
  def MineBlock(self) -> bytes:
    """ Find a nonce value that gives us a hash of some pattern.
    Bitcoin accepts a hash starting with 10 zeros (could be more).
    We will use a pattern that gives 3 zeros just to make it faster
    """
    tempHash = self.hdr.CalculateHash(self.signature)
    difficulty = 2
    while not tempHash.startswith(b'\x00' * difficulty):
      self.hdr.nonce += 1
      tempHash = self.hdr.CalculateHash(self.signature)
    self.hdr.hash = tempHash
    return self.hdr.hash
  
  def IsBlockValid(self) -> bool:
    if self.hdr.hash == self.hdr.CalculateHash(self.signature):
      return True
    else:
      return False
  
  def __repr__(self) -> str:
    return f"""Block({self.hdr}
  signature={self.signature}
)"""


      