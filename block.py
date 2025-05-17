import time
import hashlib
from pprint import pprint, pformat

VERSION=1

class BlockHeader:
  def __init__(self):
    self.SetNull()

  def SetNull(self):
    self.version = 0
    self.time: float = 0
    self.hashPrevBlock: bytes = b''  # Hash is stored real (32 bytes)
    self.hash: bytes = b''            # Hash is stored real (32 bytes)
    self.nonce: int = 0

  # Calculate the hash for all the block contents
  def CalculateHash(self, blockData: bytes=b'') -> bytes:
    # buffer = []
    # buffer.append(str(self.version))
    # buffer.append(str(self.time))
    # buffer.append(self.hashPrevBlock)
    # buffer.append(str(self.nonce))
    # if blockData is not None:
    #   buffer.append(str(blockData))
    # bufferStr = "".join(buffer)
    # bufferStr = bufferStr.encode()
    # return hashlib.sha256(bufferStr).digest()
    buffer = bytearray()
    buffer.append(self.version)
    buffer.extend(str(self.time).encode())
    buffer.extend(self.hashPrevBlock)
    buffer.extend(str(self.nonce).encode())
    if blockData != b'':
      buffer.extend(blockData)
    return hashlib.sha256(buffer).digest()
  
  def __repr__(self):
     return f"""BlockHeader(
  version={self.version},
  time={self.time},
  prev={self.hashPrevBlock},
  hash={self.hash}, 
  nonce={self.nonce})"""

class Block:
  """ For simplicty in this project, we will consider one document
  to be in a seperate block. This blockchain will have no concept of
  transactions where multiple documents are combined into a single block.
  This would have increase storage requirements of each node in the future.
  The mining frequency will also might overload the network in the future.
  """
  def __init__(self) -> None:
    self.hdr = BlockHeader()
    self.signature: bytes = b''
  
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

class Chain:
  def __init__(self) -> None:
    self.localChain: list[Block] = []
  
  def SearchByBlockHash(self, hash: bytes) -> Block | None:
    for b in self.localChain:
      if b.hdr.hash == hash:
        return b
    return None
  
  def ModifyBlockByHash(self, hash: bytes) -> None:
    targetBlock = self.SearchByBlockHash(hash)
    if targetBlock is not None:
      pass
    
  def InsertBlockToChain(self, prevBlock: Block, block: Block) -> None:
    """ Insert block after prevBlock. Each block after prev block has to
    be mined and validated.
    """
    if prevBlock.hdr.hash is not None:
      prevBlockIdx = self.GetBlockIdx(prevBlock.hdr.hash)
      if prevBlockIdx is None:
        raise ValueError("Cannot find prevBlock")
      block.hdr.hashPrevBlock = prevBlock.hdr.hash
      block.hdr.time = time.time()
      block.hdr.version = VERSION
      self.localChain.insert(prevBlockIdx + 1, block)
      for idx in range(prevBlockIdx + 1, len(self.localChain)):
        self.localChain[idx].hdr.hashPrevBlock = self.localChain[idx - 1].hdr.hash
        if not self.localChain[idx].IsBlockValid():
          self.localChain[idx].MineBlock()
          
  def AddBlockToChain(self, block: Block) -> None:
    """ Insert as the latest block to the chain
    """
    if len(self.localChain) > 0:
      block.hdr.hashPrevBlock = self.localChain[-1].hdr.hash
      block.hdr.time = time.time()
      block.hdr.version = VERSION
      block.MineBlock()
      if block.IsBlockValid():
        self.localChain.append(block)
    else:
      raise AssertionError("Add genesis block")
    
    
  def CheckChainIntegrity(self) -> bool:
    for idx in range(len(self.localChain)):
      if idx > 0:
        if self.localChain[idx].hdr.hashPrevBlock != self.localChain[idx - 1].hdr.hash:
          return False
        if not self.localChain[idx].IsBlockValid():
          return False
      else:
        # Genesis block case
        if not self.localChain[idx].IsBlockValid():
          return False
    return True
    
  def CreateGenesisBlock(self) -> None:
    if len(self.localChain) == 0:
      genesis = Block()
      genesis.hdr.version = VERSION
      genesis.signature = b'genesis'
      genesis.hdr.time = time.time()
      genesis.hdr.hashPrevBlock = b'0' * 32
      genesis.hdr.hash = genesis.hdr.CalculateHash(genesis.signature)
      genesis.MineBlock()
      if genesis.IsBlockValid():
        self.localChain.append(genesis)
      else:
        raise ValueError("Genesis block is not valid")
    else:
      raise AssertionError("Genesis block has already been mined")
     
  def GetBlockIdx(self, blockHash: bytes) -> int | None:
    for idx in range(len(self.localChain)):
      if self.localChain[idx].hdr.hash == blockHash:
        return idx
    return None

  def GetLastBlock(self) -> Block:
    return self.localChain[-1]

  def GetGenesisBlock(self) -> Block:
    return self.localChain[0]
  
  def __iter__(self):
    return self.localChain.__iter__()
      
if __name__ == "__main__":
  chain = Chain()
  bloc = Block()
  bloc.signature = b'hello world1'
  chain.CreateGenesisBlock()
  chain.AddBlockToChain(bloc)
  bloc2 = Block()
  bloc2.signature = b'hello world2'
  chain.InsertBlockToChain(chain.GetGenesisBlock(), bloc2)
  for i in chain:
    print(i)

  print("Chain Integrity: ", chain.CheckChainIntegrity())