from primitives.block import *
from primitives.chain import Chain
from net.message import *

if __name__ == "__main__":
  chain = Chain()
  bloc = Block()
  bloc.signature = b'0' * 63 + b'1'
  bloc.pubkey = b'0' * 32
  bloc.fileHash = b'0' * 32
  chain.CreateGenesisBlock()
  chain.AddBlockToChain(bloc)
  bloc2 = Block()
  bloc2.signature = b'0' * 63 + b'2'
  bloc2.pubkey = b'1' * 32
  bloc2.fileHash = b'1' * 32
  chain.AddBlockToChain(bloc2)
  
  invMessage = InvMsg()
  invMessage.blockCount = 2
  invMessage.blocks.append(bloc)
  invMessage.blocks.append(bloc2)
  invMsgBuf = invMessage.Serialize()
  print("-----")
  print(invMessage.Deserialize(invMsgBuf))
