import time
from primitives.block import Block, VERSION

GENESIS_BLOCK_SIG = b'genesis'
class Chain:
    """Immuatable list of Blocks. All chains must call CreateGenesisBlock
    before adding new blocks into the chain
    """

    def __init__(self) -> None:
        self.localChain: list[Block] = []

    def SearchByBlockHash(self, hash: bytes) -> Block | None:
        for b in self.localChain:
            if b.hdr.hash == hash:
                return b
        return None

    def AddBlockToChain(self, block: Block, check_sig=False) -> bytes:
        """Insert as the latest block to the chain. Return the hash of the
        new block"""
        if len(self.localChain) > 0:
            block.hdr.hashPrevBlock = self.localChain[-1].hdr.hash
            block.hdr.time = time.time()
            block.hdr.version = VERSION
            block.MineBlock()
            if block.IsBlockValid(check_sig=check_sig):
                self.localChain.append(block)
                return self.GetLastBlock().hdr.hash
            else:
                raise ValueError('Block is not valid')
        else:
            raise AssertionError("Add genesis block")

    def CheckChainIntegrity(self, check_sig=False) -> bool:
        for idx in range(len(self.localChain)):
            if idx > 0:
                if (
                    self.localChain[idx].hdr.hashPrevBlock
                    != self.localChain[idx - 1].hdr.hash
                ):
                    return False
                if not self.localChain[idx].IsBlockValid(check_sig=check_sig):
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
            genesis.signature = GENESIS_BLOCK_SIG
            genesis.hdr.time = 0
            genesis.hdr.hashPrevBlock = b"0" * 32
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

    def __len__(self):
        return len(self.localChain)

    def __getitem__(self, key):
        if isinstance(key, bytes):
            # Block hash
            blk = self.SearchByBlockHash(key)
            if blk is None:
                raise KeyError(f'{key} block not found')
            else:
                return blk
        elif isinstance(key, int):
            # Block index
            if key < 0 or key >= len(self.localChain):
                raise IndexError('Out of bounds access for chain')
            else:
                return self.localChain[key]
        else:
            raise KeyError('Unknown key for chain')