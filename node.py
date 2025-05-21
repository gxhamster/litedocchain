import asyncio
import logging
import threading
import argparse
import dataclasses
import socket
from primitives.chain import Chain
from net.message import *

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.DEBUG)

@dataclasses.dataclass
class Conn:
    addr: str
    port: int
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

class NetNode:
    def __init__(self, servAddr: str, servPort: int = 3333) -> None:
        self.servAddr = servAddr
        self.servPort = servPort
        self.peers: list[Conn] = []     # Other connected nodes
        self.clients: list[Conn] = []   # Users connected to this node
        self.chain = Chain()
        
    async def async_ser_callback(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info("peername")
        logging.debug(f"Connected by: addr={addr[0]}, port={addr[1]}")
        while True:
            data = await reader.read(2048)
            if data == b"":
                logging.debug("Peer/Client probably sent an EOF")
                break
            if data.startswith(MAGIC_HDR_VALUE):
                hdrSize = MsgHdr.struct.size
                hdr = MsgHdr()
                hdr = hdr.Deserialize(data[:hdrSize])
                if hdr.command == MsgType.NOMSG:
                    print(hdr.command)
                elif hdr.command == MsgType.GETBLOCKMSG:
                    logging.debug("Received: msg=MsgType.GETBLOCKMSG, dir=[peer -> node]")
                    getBlockMsg = GetBlocksMsg()
                    getBlockMsg = getBlockMsg.Deserialize(data)
                    startIdx = self.chain.GetBlockIdx(getBlockMsg.highestHash)
                    endIdx = self.chain.GetBlockIdx(getBlockMsg.stoppingHash)
                    if endIdx is None or getBlockMsg.stoppingHash.startswith(b'0' * 32):
                        # No stopping limit (get full chain)
                        endIdx = len(self.chain) - 1
                    if startIdx is None:
                        logging.debug("MsgType.GETBLOCKMSG: Cannot determine range ({startIdx}, {endIdx})")
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
                            logging.debug(f"Sending: msg=MsgType.InvMsg, dir=[node -> peer], blocks={len(blocksToSend)}")
                            writer.write(invMsg.Serialize())
                            await writer.drain()
                            
                elif hdr.command == MsgType.BLOCKDATAMSG:
                    # Received blocks from clients
                    logging.debug("Received: msg=MsgType.BLOCKDATAMSG, dir=[client -> node]")
                    bMsg = BlockDataMsg()
                    payload = bMsg.Deserialize(data)
                    if not payload.block.IsBlockValid(check_sig=True):
                        # Verify the block contents are correct
                        logging.debug("Received an invalid block from a client!")
                    else:
                        # Mine the block
                        # Add the block to localchain
                        payload.block.MineBlock()
                        logging.debug(f"Mined block: nonce={payload.block.hdr.nonce}")
                        self.chain.AddBlockToChain(payload.block)
                        if not self.chain.CheckChainIntegrity(check_sig=True):
                            logging.debug("Chain integrity checks failed")
                            # Remove block from chain
                            self.chain.localChain.pop()
                            # ACK to client to tell block failed
                            ackMsg = AckMsg()
                            ackMsg.nonce = 13
                            writer.write(ackMsg.Serialize())
                            await writer.drain()
                        else:
                            logging.debug(f"Added block: hash={self.chain.GetLastBlock().hdr.hash.hex()}")
                            invMsg = InvMsg()
                            invMsg.blockCount = 1
                            invMsg.blocks.append(self.chain.GetLastBlock())
                            # Broadcast block to connected peers if available
                            logging.debug(f"Sending: msg=MsgType.InvMsg (Broadcast), peers={len(self.peers)}")
                            for peer in self.peers:
                                peer.writer.write(invMsg.Serialize())
                                await peer.writer.drain()
                                logging.debug(f"Sending: msg=MsgType.InvMsg, peer={peer.addr}, peer_port={peer.port}")
                            
                            # Send an ACK to the client to tell that the block has
                            # been propagated to all nodes on the network
                            ackMsg = AckMsg()
                            ackMsg.nonce = 12
                            writer.write(ackMsg.Serialize())
                            await writer.drain()
                            
                elif hdr.command == MsgType.VERSION:
                    verMsg = VersionMsg()
                    verMsg.Deserialize(data)
                    sockAddr = socket.inet_ntoa(verMsg.connAddr)
                    if verMsg.connType == VersionConnType.CLIENT:
                        logging.debug(f"Received: msg=MsgType.VERSION, type=CLIENT")
                        self.clients.append(Conn(sockAddr, verMsg.connPort, reader, writer))
                    elif verMsg.connType == VersionConnType.NODE:
                        self.peers.append(Conn(sockAddr, verMsg.connPort, reader, writer))
                        logging.debug(f"MsgType.VERSION: type=NODE")
                    else:
                        logging.debug("MsgType.VERSION: connType=UNKNOWN")
                    
                        
                else:
                    logging.debug("Invalid MsgType")
                    assert "Invalid MsgType" == 0

        # TODO: Need to remove this socket from either list of peers
        # or clients
        writer.close()
        logging.debug(f"Disconnected: addr={addr[0]}, port={addr[1]}")
        await writer.wait_closed()

    async def async_server(self):
        server = await asyncio.start_server(
            self.async_ser_callback, self.servAddr, self.servPort
        )
        
        for sock in server.sockets:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
        logging.debug(f"Running node: addr={addrs}")

        async with server:
            await server.serve_forever()

    def run_async_server(self):
        asyncio.run(self.async_server())

    async def async_client(self, thisPeerAddr: str, thisPeerPort: int):
        reader, writer = await asyncio.open_connection(
            thisPeerAddr, thisPeerPort)
        logging.debug(f"Connecting: peer_addr={thisPeerAddr}, peer_port={thisPeerPort}")
        logging.debug(f"Me: addr={writer.get_extra_info("sockname")[0]}, peer_port={writer.get_extra_info("sockname")[1]}")
        self.peers.append(Conn(thisPeerAddr, thisPeerPort, reader, writer))
        
        if len(self.peers) <= 0:
            logging.debug("No available peers yet")
            writer.close()
            
        # Send a VERSION msg
        verMsg = VersionMsg()
        verMsg.connType = VersionConnType.NODE
        sockInfo = writer.get_extra_info("sockname")
        verMsg.connAddr = socket.inet_aton(sockInfo[0])
        verMsg.connPort = sockInfo[1]
        writer.write(verMsg.Serialize())
        await writer.drain()
        logging.debug(f"Sending: msg=MsgType.VERSION, type=NODE")
        
        # Initiate the IBD (Initial Block Download)  
        getBlockMsg = GetBlocksMsg()
        getBlockMsg.highestHash = self.chain.GetLastBlock().hdr.hash
        getBlockMsg.stoppingHash = b'0' * 32
        getBlockMsg.SetChecksumSize()
        peerWriterSock = self.peers[-1].writer  # For now just select last peer
        peerReaderSock = self.peers[-1].reader
        peerWriterSock.write(getBlockMsg.Serialize())
        logging.debug(f"Sending: msg=GetBlockMsg, peer_addr={peerWriterSock.get_extra_info("peername")[0]}, peer_port={peerWriterSock.get_extra_info("peername")[1]}")
        
        # Note(iyaan): Maybe hardcoding the reading size is not ideal
        # What happens when we are reading a large InvMsg?
        while True:
            data = await peerReaderSock.read(2048)
            if data == b'':
                logging.debug("Server probably sent an EOF")
                break
            elif data.startswith(MAGIC_HDR_VALUE):
                hdrSize = MsgHdr.struct.size
                hdr = MsgHdr()
                hdr = hdr.Deserialize(data[:hdrSize])
                if hdr.command == MsgType.INVMSG:
                    logging.debug(f"Received: msg=MsgType.InvMsg, peer_addr={thisPeerAddr}, peer_port={thisPeerPort}")
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
                            self.chain.CheckChainIntegrity(check_sig=True)
                            logging.debug(f"Added block: {block.hdr.hash.hex()}")
                            peersToSend = filter(lambda peer: peer.addr != thisPeerAddr and peer.port != thisPeerPort , self.peers)
                            for peer in peersToSend:
                                peer.writer.write(invMsg.Serialize())
                                logging.debug(f"Sending: msg=MsgType.InvMsg, peer={peer.addr}, peer_port={peer.port}")
                                await peer.writer.drain()

        writer.close()
        # Need to remove this socket from list of peers
        unremoved_peers = filter(lambda peer: peer.addr != thisPeerAddr and peer.port != thisPeerPort , self.peers)
        self.peers = list(unremoved_peers)
        await writer.wait_closed()

    def run_async_client(self, peerAddr: str, peerPort: int):
        asyncio.run(self.async_client(peerAddr, peerPort))
    

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
    # print(args)
    
    n = NetNode(args.addr, args.port)
    n.chain.CreateGenesisBlock()
    logging.debug(f"Added genesis block: hash={n.chain.GetGenesisBlock().hdr.hash.hex()}")
    serv_thread = threading.Thread(target=n.run_async_server)
    serv_thread.start()
    
    if args.paddr is None or args.pport is None:
        logging.debug("Cannot connect to any peer, no peer address and port")
    else:
        n.run_async_client(args.paddr, args.pport)
    
    try:
        serv_thread.join()
    except KeyboardInterrupt:
        logging.info("Shutting down node")