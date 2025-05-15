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
  def CalculateHash(self) -> str:
    buffer = []
    buffer.append(str(self.version))
    buffer.append(str(self.time))
    buffer.append(str(self.hashPrevBlock))
    buffer.append(str(self.hash))
    buffer.append(str(self.nonce))
    bufferStr = "".join(buffer)
    bufferStr = bufferStr.encode()

    return hashlib.sha256(bufferStr).hexdigest()
  
  def isBlockValid(self) -> bool:
    if self.hash == self.CalculateHash():
      return True
    else:
      return False


  def __repr__(self):
     return f"Block(version={self.version}, time={self.time}, prev={self.hashPrevBlock} hash={self.hash})"


b = BlockHeader()
print(b)
print(b.CalculateHash())
b.time = time.time()
print(b.CalculateHash())