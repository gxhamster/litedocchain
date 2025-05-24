from primitives.block import *
from primitives.chain import Chain
from net.message import *
from primitives.block import Block, VERSION
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

class TestChain(unittest.TestCase):
    def setUp(self):
        self.chain = Chain()

    def test_create_genesis_block(self):
        self.chain.CreateGenesisBlock()
        self.assertEqual(len(self.chain), 1)
        genesis = self.chain.GetGenesisBlock()
        self.assertEqual(genesis.signature, b"genesis")
        self.assertEqual(genesis.hdr.time, 0)
        self.assertEqual(genesis.hdr.version, VERSION)
        self.assertEqual(genesis.hdr.hashPrevBlock, b"0" * 32)

    def test_create_genesis_block_twice_raises(self):
        self.chain.CreateGenesisBlock()
        with self.assertRaises(AssertionError, msg='Genesis block cannot be created twice'):
            self.chain.CreateGenesisBlock()

    def test_add_block_to_chain(self):
        self.chain.CreateGenesisBlock()
        block = Block()
        block.signature = b"block1"
        self.chain.AddBlockToChain(block)
        self.assertEqual(len(self.chain), 2)
        self.assertEqual(self.chain.GetLastBlock().signature, b"block1")

    def test_add_block_without_genesis_raises(self):
        block = Block()
        with self.assertRaises(AssertionError):
            self.chain.AddBlockToChain(block)

    def test_search_by_block_hash(self):
        self.chain.CreateGenesisBlock()
        block = Block()
        block.signature = b"block2"
        self.chain.AddBlockToChain(block)
        found = self.chain.SearchByBlockHash(self.chain.GetLastBlock().hdr.hash)
        if found:
            self.assertIsNotNone(found, 'Cannot find by block hash')
            self.assertEqual(found.signature, b"block2")

    def test_search_by_block_hash_not_found(self):
        self.chain.CreateGenesisBlock()
        result = self.chain.SearchByBlockHash(b"notfound" * 4)
        self.assertIsNone(result)

    def test_check_chain_integrity(self):
        priv_key = Ed25519PrivateKey.generate()
        def make_blk(count: int):
            blk = Block()
            contents = b'hello world' + str(count).encode()
            blk.fileHash = hashlib.sha256(contents).digest()
            blk.signature = priv_key.sign(blk.fileHash)
            blk.pubkey = priv_key.public_key().public_bytes_raw()
            return blk
        
        self.chain.CreateGenesisBlock()
        CHAIN_LEN = 4
        for i in range(CHAIN_LEN):
            blk = make_blk(i)
            self.chain.AddBlockToChain(blk)
        
        # Try to change content of a block
        self.assertTrue(self.chain.CheckChainIntegrity(check_sig=True), 'Correct order of blocks')
        self.chain.localChain[2].fileHash = b''
        self.assertFalse(self.chain.CheckChainIntegrity(check_sig=True), 'Incorrect order of blocks')

    def test_getitem_chain(self):
        self.chain.CreateGenesisBlock()
        blk = Block()
        blk.fileHash = b'Hello'
        h = self.chain.AddBlockToChain(blk)
        
        with self.assertRaises(KeyError, msg='Getting a block with a non-existent hash'):
            self.chain[b'whatever']
        
        self.assertTrue(self.chain[h].hdr.hash == h, 'Correct indexing with hash')
        
        with self.assertRaises(KeyError, msg='Wrong indexing key type'):
            self.chain["whatever"]
        
        with self.assertRaises(IndexError, msg='Out of bounds access'):
            self.chain[2]
        self.assertTrue(self.chain[1].hdr.hash == h, 'Correct index with int')
        
        
if __name__ == "__main__":
    unittest.main(verbosity=2)
