import asyncio
import logging
import threading
import argparse
from primitives.block import Block
from primitives.chain import Chain
from net.message import MAGIC_HDR_VALUE, MsgHdr, BlockDataMsg, MsgType, GetBlocksMsg, InvMsg

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.DEBUG)

class NetNode:
    def __init__(self, servAddr: str, servPort: int = 3333) -> None:
        self.servAddr = servAddr
        self.servPort = servPort
        self.peers: list[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = []     # Other connected nodes
        self.clients = []   # Users connected to this node
        self.chain = Chain()
        
    async def asyncServerCallback(self, reader, writer):
        data = await reader.read(2048)
        addr = writer.get_extra_info("peername")
        logging.debug(f"Connected by: {addr}")
        if data == b"":
            logging.debug("Peer/Client probably sent an EOF")
        if data.startswith(MAGIC_HDR_VALUE):
            hdrSize = MsgHdr.struct.size
            hdr = MsgHdr()
            hdr = hdr.Deserialize(data[:hdrSize])
            if hdr.command == MsgType.NOMSG:
                print(hdr.command)
            elif hdr.command == MsgType.GETBLOCKMSG:
                logging.debug("MsgType.GETBLOCKMSG [peer -> node]")
                getBlockMsg = GetBlocksMsg()
                getBlockMsg = getBlockMsg.Deserialize(data)
                startIdx = self.chain.GetBlockIdx(getBlockMsg.highestHash)
                endIdx = self.chain.GetBlockIdx(getBlockMsg.stoppingHash)
                if endIdx is None or getBlockMsg.stoppingHash.startswith(b'0' * 32):
                    endIdx = len(self.chain) - 1
                if startIdx is None:
                    logging.debug("MsgType.GETBLOCKMSG: Cannot determine range ({startIdx}, {endIdx})")
                    print(getBlockMsg)
                else:
                    if getBlockMsg.highestHash == self.chain.GetLastBlock().hdr.hash:
                        logging.debug("MsgType.GETBLOCKMSG: Two nodes have same blockchain, ignore")
                    else:
                        blocksToSend = []
                        for idx, block in enumerate(self.chain):
                            if idx > startIdx and idx <= endIdx:
                                blocksToSend.append(block)
                            
                        # Send an Inv message with all the serialized blocks packed together
                        invMsg = InvMsg()
                        invMsg.blockCount = len(blocksToSend)
                        invMsg.blocks = blocksToSend
                        logging.debug(f"MsgType.InvMsg: [node -> peer] {len(blocksToSend)}")
                        writer.write(invMsg.Serialize())
                        await writer.drain()
                        
            elif hdr.command == MsgType.BLOCKDATAMSG:
                # Received blocks from clients
                # Verify the block contents are correct
                # Mine the block
                # Add the block to localchain
                # Broadcast block to other nodes if available
                logging.debug("MsgType.BLOCKDATAMSG [client -> node]")
                bMsg = BlockDataMsg()
                payload = bMsg.Deserialize(data)
                if not payload.block.IsBlockValid(check_sig=True):
                    logging.debug("Received an invalid block from a client!")
                else:
                    payload.block.MineBlock()
                    logging.debug(f"Mined block: nonce = {payload.block.hdr.nonce}")
                    self.chain.AddBlockToChain(payload.block)
                    if not self.chain.CheckChainIntegrity(check_sig=True):
                        logging.debug("Chain integrity checks failed")
                        # Remove block from chain
                        self.chain.localChain.pop()
                    else:
                        logging.debug(f"Added block: {self.chain.GetLastBlock().hdr.hash.hex()}")
                        invMsg = InvMsg()
                        invMsg.blockCount = 1
                        invMsg.blocks.append(self.chain.GetLastBlock())
                        logging.debug(f"MsgType.InvMsg: [node -> peer]: 1 block from client")
                        # writer.write(invMsg.Serialize())
                        # await writer.drain()
            else:
                logging.debug("Invalid MsgType")
                assert "Invalid MsgType" == 0

        # writer.write(data)
        # await writer.drain()
        await writer.wait_closed()

    async def asyncServer(self):
        server = await asyncio.start_server(
            self.asyncServerCallback, self.servAddr, self.servPort
        )

        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        logging.debug(f"Serving on {addrs}")

        async with server:
            await server.serve_forever()

    def runAsyncServer(self):
        asyncio.run(self.asyncServer())

    async def asyncClient(self, peerAddr: str, peerPort: int):
        reader, writer = await asyncio.open_connection(
            peerAddr, peerPort)

        self.peers.append((reader, writer))
        
        if len(self.peers) <= 0:
            logging.debug("No available peers yet")
            writer.close()
        
        # Initiate the IBD (Initial Block Download)  
        getBlockMsg = GetBlocksMsg()
        getBlockMsg.highestHash = self.chain.GetLastBlock().hdr.hash
        getBlockMsg.stoppingHash = b'' * 32
        getBlockMsg.SetChecksumSize()
        peerWriterSock = self.peers[-1][1]  # For now just select last peer
        peerReaderSock = self.peers[-1][0] 
        peerWriterSock.write(getBlockMsg.Serialize())
        logging.debug(f"Sent GetBlockMsg to {peerWriterSock.get_extra_info("peername")}")
        # Note(iyaan): Maybe hardcoding the reading size is not ideal
        # What happens when we are reading a large InvMsg?
        data = await peerReaderSock.read(2048)
        if data == b'':
            logging.debug("Server probably sent an EOF")
        elif data.startswith(MAGIC_HDR_VALUE):
            hdrSize = MsgHdr.struct.size
            hdr = MsgHdr()
            hdr = hdr.Deserialize(data[:hdrSize])
            if hdr.command == MsgType.INVMSG:
                logging.debug("Received MsgType.InvMsg")
                invMsg = InvMsg()
                invMsg.Deserialize(data)
                for block in invMsg.blocks:
                    # Find the block which matches the hashPrev
                    targetIdx = -1
                    for idx, localBlock in enumerate(self.chain):
                        if localBlock.hdr.hash == block.hdr.hashPrevBlock:
                            targetIdx = idx
                            break
                    if targetIdx == -1:
                        logging.debug(f"Cannot add block: {block.hdr.hash.hex()}")
                    else:
                        self.chain.localChain.insert(targetIdx + 1, block)
                        logging.debug(f"Added block: {block.hdr.hash.hex()}")
                        self.chain.CheckChainIntegrity(check_sig=True)
        
        await writer.wait_closed()

    def runAsyncClient(self, peerAddr: str, peerPort: int):
        asyncio.run(self.asyncClient(peerAddr, peerPort))
    

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='node',
        description="""Node program for litedocchain""",
    )
    parser.add_argument('-a', '--addr', help='node server address', default='localhost')
    parser.add_argument('-p', '--port', type=int, help='node server port', default=3333)
    parser.add_argument('--paddr', help='peer address')
    parser.add_argument('--pport', type=int, help='peer port')
    args = parser.parse_args()
    print(args)
    
    n = NetNode(args.addr, args.port)
    n.chain.CreateGenesisBlock()
    logging.debug(f"Added genesis block: {n.chain.GetGenesisBlock().hdr.hash}")
    servThread = threading.Thread(target=n.runAsyncServer)
    servThread.start()
    
    if args.paddr is None or args.pport is None:
        logging.debug("Cannot connect to any peer, no peer address and port")
    else:
        n.runAsyncClient(args.paddr, args.pport)
    
    try:
        servThread.join()
    except KeyboardInterrupt:
        logging.info("Shutting down node")