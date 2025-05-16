import time
import hashlib

VERSION=0.1

class BlockHeader:
  def __init__(self):
    self.SetNull()

  def SetNull(self):
    self.version = 0
    self.time: float = 0
    self.hashPrevBlock: str | None = None
    self.hash: str | None = None
    self.nonce: int = 0

  # Calculate the hash for all the block contents
  def CalculateHash(self, blockData=None) -> str:
    buffer = []
    buffer.append(str(self.version))
    buffer.append(str(self.time))
    buffer.append(str(self.hashPrevBlock))
    buffer.append(str(self.hash))
    buffer.append(str(self.nonce))
    if blockData is not None:
      buffer.append(str(blockData))
    bufferStr = "".join(buffer)
    bufferStr = bufferStr.encode()
    return hashlib.sha256(bufferStr).hexdigest()
  
  def isBlockValid(self) -> bool:
    if self.hash == self.CalculateHash():
      return True
    else:
      return False

  def __repr__(self):
     return f"BlockHeader(version={self.version}, time={self.time}, prev={self.hashPrevBlock} hash={self.hash}, nonce={self.nonce})"

class Block:
  """ For simplicty in this project, we will consider one document
  to be in a seperate block. This blockchain will have no concept of
  transactions where multiple documents are combined into a single block.
  This would have increase storage requirements of each node in the future.
  The mining frequency will also might overload the network in the future.
  """
  def __init__(self) -> None:
    self.header = BlockHeader()
    self.signature: str | None = None
    self.index = 0

b = BlockHeader()
print(b)
print(b.CalculateHash())
b.time = time.time()
print(b.CalculateHash())