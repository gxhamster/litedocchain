import hashlib
from typing import Self
from struct import Struct
from serialization.serialize import Serializable
from crypt.ed25519 import VerifySigPubkey

VERSION=1

class BlockHeader(Serializable):
  struct = Struct('>Bd32s32sI')
  def __init__(self):
    self.SetNull()

  def SetNull(self):
    super().__init__()
    self.version = VERSION            # 1 byte char
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
     return f"""BlockHeader(version={self.version}, time={self.time}, prev={self.hashPrevBlock}, hash={self.hash}, nonce={self.nonce})"""

class Block(Serializable):
  """ For simplicty in this project, we will consider one document
  to be in a seperate block. This blockchain will have no concept of
  multiple transactions where multiple documents are combined into a single block.
  This would have increase storage requirements of each node in the future.
  The mining frequency will also might overload the network in the future.
  """
  struct = Struct('>64s32s32s')
  def __init__(self) -> None:
    super().__init__()
    self.hdr = BlockHeader()
    self.signature: bytes = b''   # 64 byte Ed25519 signature of fileHash
    self.fileHash: bytes = b''    # 32 byte sha256 of file data 
    self.pubkey: bytes = b''      # 32 byte pubkey of private/public key pair of file owner
  
  def Serialize(self) -> bytes:
    hdrBytes = self.hdr.Serialize()
    fieldBytes = self.struct.pack(self.signature, self.fileHash, self.pubkey)
    return hdrBytes + fieldBytes
  
  def Deserialize(self, buffer: bytes) -> Self:
    hdrSize = self.hdr.struct.size
    self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
    sigBytes, fHash, pKey = self.struct.unpack(buffer[hdrSize:])
    self.signature, self.fileHash, self.pubkey = sigBytes, fHash, pKey
    return self
  
  def MineBlock(self) -> bytes:
    """ Find a nonce value that gives us a hash of some pattern.
    Bitcoin accepts a hash starting with 10 zeros (could be more).
    We will use a pattern that gives 3 zeros just to make it faster.
    Also sets the new hash to the block.
    """
    tempHash = self.hdr.CalculateHash(self.signature + self.fileHash + self.pubkey)
    difficulty = 2
    while not tempHash.startswith(b'\x00' * difficulty):
      self.hdr.nonce += 1
      tempHash = self.hdr.CalculateHash(self.signature + self.fileHash + self.pubkey)
    self.hdr.hash = tempHash
    return self.hdr.hash
  
  def IsBlockValid(self, check_sig=False) -> bool:
    if self.hdr.hash != self.hdr.CalculateHash(self.signature + self.fileHash + self.pubkey):
      return False
    if check_sig:
      if not VerifySigPubkey(self.pubkey, self.signature, self.fileHash):
        return False
    return True
  
  def __repr__(self) -> str:
    return f"""Block({self.hdr}, signature={self.signature}, fileHash={self.fileHash}, pubkey={self.pubkey})"""


      