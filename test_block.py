import unittest
import hashlib
import struct
import copy
from primitives.block import *
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


class TestBlockHeader(unittest.TestCase):
    def test_blk_hdr_size(self):
        blk_hdr = BlockHeader()
        self.assertTrue(
            blk_hdr.struct is not None, "Block header must have a struct defined"
        )
        self.assertEqual(
            blk_hdr.struct.size, 77, "Block header struct size must be 77 bytes"
        )

    def test_blk_hdr_serialize(self):
        blk_hdr = BlockHeader()
        blk_hdr.version = 1
        blk_hdr.time = 2000
        blk_hdr.hashPrevBlock = b"0" * 32
        blk_hdr.hash = b"1" * 32
        blk_hdr.nonce = 12000
        expected_buf = b"\x01@\x9f@\x00\x00\x00\x00\x000000000000000000000000000000000011111111111111111111111111111111\x00\x00.\xe0"
        serial_buf = blk_hdr.Serialize()
        self.assertEqual(
            serial_buf, expected_buf, "Serialized blk hdr contents not match"
        )
        self.assertEqual(len(serial_buf), 77)

    def test_blk_hdr_deserialze(self):
        blk_hdr = BlockHeader()
        blk_hdr.version = 1
        blk_hdr.time = 2000
        blk_hdr.hashPrevBlock = b"0" * 32
        blk_hdr.hash = b"1" * 32
        blk_hdr.nonce = 12000

        temp_blk_hdr = copy.deepcopy(blk_hdr)
        buf = temp_blk_hdr.Serialize()
        temp_blk_hdr.Deserialize(buf)
        for k, _ in temp_blk_hdr.__dict__.items():
            self.assertTrue(
                temp_blk_hdr.__dict__[k] == blk_hdr.__dict__[k],
                "Block header changed after deserialize",
            )

    def test_blk_hdr_hash(self):
        blk_hdr = BlockHeader()
        blk_hdr.version = 1
        blk_hdr.time = 2000
        blk_hdr.hashPrevBlock = b"0" * 32
        blk_hdr.hash = b"1" * 32
        blk_hdr.nonce = 12000

        # Hash value length must always remain at 32 bytes
        for i in range(12000):
            blk_hdr.nonce = i
            self.assertEqual(len(blk_hdr.CalculateHash()), 32)
        blk_hdr.nonce = 12000

        # Do not include the hash field when calculating hash
        wrong_hash = hashlib.sha256(blk_hdr.Serialize()).digest()
        self.assertNotEqual(
            wrong_hash, blk_hdr.CalculateHash(), "Do not include hash field"
        )

        packStructNoHash = struct.Struct(">Bd32sI")
        buf = packStructNoHash.pack(
            blk_hdr.version, blk_hdr.time, blk_hdr.hashPrevBlock, blk_hdr.nonce
        )
        self.assertEqual(hashlib.sha256(buf).digest(), blk_hdr.CalculateHash())


class TestBlock(unittest.TestCase):
    def test_block_format(self):
        blk = Block()
        self.assertTrue(
            blk.struct is not None, "Block header must have a struct defined"
        )
        self.assertIsInstance(blk, Serializable)
        self.assertTrue(blk.struct.size == 128, "Block fields size should be 128")
        self.assertIsNotNone(blk.hdr, "Block must have BlockHeader")

    def test_block_mine(self):
        blk = Block()
        self.assertTrue(
            blk.MineBlock().startswith(b"\x00" * BLK_DIFFICULTY),
            "Did not mine according to difficulty",
        )

    def test_block_valid(self):
        priv_key = Ed25519PrivateKey.generate()
        blk = Block()
        contents = b"hello world"
        blk.fileHash = hashlib.sha256(contents).digest()
        blk.signature = priv_key.sign(blk.fileHash)
        blk.pubkey = priv_key.public_key().public_bytes_raw()
        self.assertFalse(
            blk.IsBlockValid(check_sig=True), "Hash not set yet, should be false"
        )
        blk.hdr.hash = blk.hdr.CalculateHash(blk.signature + blk.fileHash + blk.pubkey)
        self.assertTrue(blk.IsBlockValid(check_sig=True), "Block is valid")
        # Tamper signature and test
        blk.signature += b"0"
        self.assertFalse(
            blk.IsBlockValid(check_sig=True), "Signature not matching, should be false"
        )


class TestRabinKarp(unittest.TestCase):
    def test_rabin_karp(self):
        self.assertEqual(RabinKarp("AABCAABCCACCAC", "BCCA"), 6)
        self.assertEqual(RabinKarp("AABCAABCCACCAC", "VCCA"), -1)
        self.assertEqual(RabinKarp("AABCAABCCACCAC", "AC"), 9)
        self.assertEqual(RabinKarp("AABCAABCCACCAC", ""), -1)
        self.assertEqual(
            RabinKarp(
                "a257129a632eb20e684fc31d99f47924b0ff1d3d6a4611dade8102504aaaa4d3",
                "a257129a632eb20e684fc31d99f47924b0ff1d3d6a4611dade8102504aaaa4d3",
            ),
            0,
        )
        self.assertEqual(RabinKarp('a257129a632eb20e684fc31d99f47924b0ff1d3d6a4611dade8102504aaaa4d3', 'd99f4792'), 23)


if __name__ == "__main__":
    unittest.main(verbosity=2)
