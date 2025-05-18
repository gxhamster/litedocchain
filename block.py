from serialization.serialize import Serializable
from primitives.block import *
from primitives.chain import *

if __name__ == "__main__":
  chain = Chain()
  bloc = Block()
  bloc.signature = b'hello world1'
  chain.CreateGenesisBlock()
  chain.AddBlockToChain(bloc)
  bloc2 = Block()
  bloc2.signature = b'hello world2'
  chain.AddBlockToChain(bloc2)
  for i in chain:
    print(i)
    
  print("Chain Integrity: ", chain.CheckChainIntegrity())
  blocBytes = bloc.Serialize()
  print(blocBytes)
  print(bloc.Deserialize(blocBytes))