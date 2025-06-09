from unittest.mock import AsyncMock, MagicMock, patch
import unittest
import asyncio
import node
from primitives.block import *
from net.message import *


class TestNetNodeServerCallback(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.node = node.NetNode("127.0.0.1", 3333)
        self.node.chain.CreateGenesisBlock()
        genesis_content = BlockContent()
        genesis_content.hdr = self.node.chain.GetGenesisBlock().hdr
        genesis_content.contents = bytearray(b"genesis")
        self.node.content_db.append(genesis_content)

        # node.run_async_server()

    async def test_node_server_callback_invalid_magic(self):
        reader = AsyncMock()
        writer = MagicMock()
        reader.read = AsyncMock(side_effect=[b"ABCD" + b"\x00" * 6, b""])
        writer.get_extra_info = MagicMock(side_effect=[("127.0.0.1", 3333)])
        await self.node.node_server_callback(reader, writer)
        writer.close.assert_called_once()

    @patch("node.getblockmsg_handle")
    async def test_node_server_getblockmsg(self, mock_func):
        reader = MagicMock()
        writer = MagicMock()
        hdr = MsgHdr(MsgType.GETBLOCKMSG)
        reader.read = AsyncMock(side_effect=[hdr.Serialize(), b""])
        writer.get_extra_info = MagicMock(side_effect=[("127.0.0.1", 3333)])
        await self.node.node_server_callback(reader, writer)
        mock_func.assert_called_once()
        writer.close.assert_called_once()
        
    async def test_node_server_getblockmsg1(self):
        reader = MagicMock()
        writer = MagicMock()
        hdr = MsgHdr(MsgType.GETBLOCKMSG)
        getBlockMsg = GetBlocksMsg()
        getBlockMsg.highestHash = self.node.chain.GetLastBlock().hdr.hash
        getBlockMsg.stoppingHash = b"0" * 32  # Get all hashes upto last
        getBlockMsg.SetChecksumSize()
        reader.read = AsyncMock(side_effect=[getBlockMsg.hdr.Serialize(), getBlockMsg.Serialize()[hdr.struct.size:], b""])
        writer.get_extra_info = MagicMock(side_effect=[("127.0.0.1", 3333)])
        await self.node.node_server_callback(reader, writer)
        writer.write.assert_not_called()

        writer.close.assert_called_once()

if __name__ == "__main__":
    unittest.main(verbosity=2)
