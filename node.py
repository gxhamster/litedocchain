import socket
import asyncio
import time
from primitives.block import Block
from primitives.chain import Chain
from net.message import MAGIC_HDR_VALUE, MsgHdr, BlockDataMsg, MsgType

class NetNode:
    def __init__(self, address: str, port: int = 3333) -> None:
        self.address = address
        self.port = port
        self.peers = []
        self.clients = []
        self.chain = Chain()
        
    async def asyncServerCallback(self, reader, writer):
        data = await reader.read(2048)
        addr = writer.get_extra_info('peername')
        if data == b'':
            pass
        if data.startswith(MAGIC_HDR_VALUE):
            hdrSize = MsgHdr.struct.size
            hdr = MsgHdr()
            hdr = hdr.Deserialize(data[:hdrSize])
            if hdr.command == MsgType.NOMSG:
                print(hdr.command)
            elif hdr.command == MsgType.GETBLOCKMSG:
                print(hdr.command)
            elif hdr.command == MsgType.BLOCKDATAMSG:
                # Received blocks from clients
                # Verify the block contents are correct
                # Mine the block
                # Add the block to localchain
                # Broadcast block to other nodes if available
                print(hdr.command)
                bMsg = BlockDataMsg()
                payload = bMsg.Deserialize(data)
                if not payload.block.IsBlockValid(check_sig=True):
                    print("Received an invalid block from a client!")
                else:
                    payload.block.MineBlock()
                    self.chain.AddBlockToChain(payload.block)
                    if not self.chain.CheckChainIntegrity():
                        print("Chain integrity checks failed")
                        # Remove block from chain
                        self.chain.localChain.pop()
                    else:
                        writer.write(f"Added block {self.chain.GetLastBlock().hdr.hash}".encode())
                    
                    
            else:
                print("Invalid MsgType")
                assert "Invalid MsgType" == 0

        writer.write(data)
        await writer.drain()
        await writer.wait_closed()
    
    async def asyncServer(self):
        server = await asyncio.start_server(
        self.asyncServerCallback, self.address, self.port)

        addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)
        print(f'Serving on {addrs}')

        async with server:
            await server.serve_forever()
            
    def runAsyncServer(self):
        asyncio.run(self.asyncServer())
    
if __name__ == "__main__":
    n = NetNode("localhost")
    n.chain.CreateGenesisBlock()
    n.runAsyncServer()
