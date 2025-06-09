import asyncio
import logging
import random
import struct
import threading
import argparse
import dataclasses
import socket
from primitives.chain import Chain
from primitives.block import BlockContent, BlockContentDB, RabinKarp
from crypt.ed25519 import verify_sig_pubkey
from net.message import *

logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    datefmt="%m/%d/%Y %I:%M:%S %p",
    level=logging.DEBUG,
)


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
        self.peers: list[Conn] = []  # Other connected nodes
        self.clients: list[Conn] = []  # Users connected to this node
        self.chain = Chain()
        self.content_db: BlockContentDB = BlockContentDB()

    async def node_server_callback(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        addr = writer.get_extra_info("peername")
        logging.debug(f"Connected by: addr={addr[0]}, port={addr[1]}")
        while True:
            hdr_bytes = await reader.read(MsgHdr.struct.size)
            if hdr_bytes == b"":
                logging.debug("Peer/Client probably sent an EOF")
                writer.close()
                logging.debug(f"Disconnected: addr={addr[0]}, port={addr[1]}")
                return
            if not hdr_bytes.startswith(MAGIC_HDR_VALUE):
                writer.close()
                return

            hdr = MsgHdr()
            hdr = hdr.Deserialize(hdr_bytes)
            msg_handler = MsgHandler(hdr, reader=reader, writer=writer)

            if hdr.command == MsgType.NOMSG:
                logging.debug("Received: msg=MsgType.NOMSG")

            elif hdr.command == MsgType.GETBLOCKMSG:
                await getblockmsg_handle(msg_handler, self)

            elif hdr.command == MsgType.BLOCKDATAMSG:
                await blockdatamsg_handle(msg_handler, self)

            elif hdr.command == MsgType.VERSION:
                await versionmsg_handle(msg_handler, self)

            elif hdr.command == MsgType.REQVERIFICATION:
                await reqvermsg_handle(msg_handler, self)

            else:
                logging.debug("Invalid MsgType")
                assert "Invalid MsgType" == 0

    async def async_server(self):
        server = await asyncio.start_server(
            self.node_server_callback, self.servAddr, self.servPort
        )

        for sock in server.sockets:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        for sock in server.sockets:
            addr, port = sock.getsockname()
            logging.debug(f"Running node: addr={addr}, port={port}")
        
        async with server:
            await server.serve_forever()

    def run_async_server(self):
        asyncio.run(self.async_server())

    async def async_client(self, thisPeerAddr: str, thisPeerPort: int):
        reader, writer = await asyncio.open_connection(thisPeerAddr, thisPeerPort)
        addr = writer.get_extra_info("peername")
        logging.debug(f"Connecting: peer_addr={addr[0]}, peer_port={addr[1]}")
        logging.debug(
            f"Me: addr={writer.get_extra_info("sockname")[0]}, peer_port={writer.get_extra_info("sockname")[1]}"
        )
        self.peers.append(Conn(addr[0], addr[1], reader, writer))

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
        getBlockMsg.stoppingHash = b"0" * 32  # Get all hashes upto last
        getBlockMsg.SetChecksumSize()
        peerWriterSock = self.peers[-1].writer  # For now just select last peer
        peerReaderSock = self.peers[-1].reader
        peerWriterSock.write(getBlockMsg.Serialize())
        logging.debug(
            f"Sending: msg=GetBlockMsg, peer_addr={peerWriterSock.get_extra_info("peername")[0]}, peer_port={peerWriterSock.get_extra_info("peername")[1]}"
        )

        # Note(iyaan): Maybe hardcoding the reading size is not ideal
        # What happens when we are reading a large InvMsg?
        while True:
            hdr_bytes = await reader.read(MsgHdr.struct.size)
            if hdr_bytes == b"":
                logging.debug("Server probably sent an EOF")
                break
            if not hdr_bytes.startswith(MAGIC_HDR_VALUE):
                break

            hdr = MsgHdr()
            hdr = hdr.Deserialize(hdr_bytes)
            msg_handler = MsgHandler(hdr, reader=reader, writer=writer)
            
            if hdr.command == MsgType.INVMSG:
                await invmsg_handle(msg_handler, self)
            else:
                break
                
        writer.close()
        logging.debug(
            f"Drop peer connection to: addr={addr[0]}, port={addr[1]}"
        )
        # Need to remove this socket from list of peers
        unremoved_peers = filter(
            lambda peer: peer.addr != addr[0] and peer.port != addr[1],
            self.peers,
        )
        self.peers = list(unremoved_peers)
        await writer.wait_closed()

    def run_async_client(self, peerAddr: str, peerPort: int):
        asyncio.run(self.async_client(peerAddr, peerPort))


@dataclasses.dataclass
class MsgHandler:
    hdr: MsgHdr
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter


async def versionmsg_handle(handler: MsgHandler, node: NetNode):
    version_msg_bytes = await handler.reader.read(handler.hdr.size)
    verMsg = VersionMsg()
    verMsg.Deserialize(handler.hdr.Serialize() + version_msg_bytes)
    sockAddr = socket.inet_ntoa(verMsg.connAddr)
    if verMsg.connType == VersionConnType.CLIENT:
        logging.debug(f"Received: msg=MsgType.VERSION, type=CLIENT")
        node.clients.append(
            Conn(sockAddr, verMsg.connPort, handler.reader, handler.writer)
        )
    elif verMsg.connType == VersionConnType.NODE:
        node.peers.append(
            Conn(sockAddr, verMsg.connPort, handler.reader, handler.writer)
        )
        logging.debug(f"MsgType.VERSION: type=NODE")
    else:
        logging.debug("MsgType.VERSION: connType=UNKNOWN")


async def invmsg_handle(handler: MsgHandler, node: NetNode):
    addr = handler.writer.get_extra_info("peername")
    logging.debug(
        f"Received: msg=MsgType.InvMsg, peer_addr={addr[0]}, peer_port={addr[1]}"
    )
    inv_msg_bytes = await handler.reader.read(handler.hdr.size)
    invMsg = InvMsg()
    invMsg.Deserialize(handler.hdr.Serialize() + inv_msg_bytes)
    for block in invMsg.blocks:
        # Find the block which matches the hashPrev
        targetIdx = -1
        for idx, localBlock in enumerate(node.chain):
            if localBlock.hdr.hash == block.hdr.hashPrevBlock:
                targetIdx = idx
                break
        if targetIdx == -1:
            logging.debug(f"Cannot add block: {block.hdr.hash.hex()}")
        else:
            node.chain.localChain.insert(targetIdx + 1, block)
            node.chain.CheckChainIntegrity(check_sig=True)
            logging.debug(f"Added block: {block.hdr.hash.hex()}")
            peersToSend = filter(
                lambda peer: peer.addr != addr[0]
                and peer.port != addr[1],
                node.peers,
            )
            for peer in peersToSend:
                peer.writer.write(invMsg.Serialize())
                logging.debug(
                    f"Sending: msg=MsgType.InvMsg, peer={peer.addr}, peer_port={peer.port}"
                )
                await peer.writer.drain()


async def reqvermsg_handle(handler: MsgHandler, node: NetNode):
    req_ver_msg_bytes = await handler.reader.read(handler.hdr.size)
    req_ver_msg = ReqVerificationMsg()
    req_ver_msg.Deserialize(handler.hdr.Serialize() + req_ver_msg_bytes)
    logging.debug(f"Received: msg=MsgType.REQVERIFICATION")

    # Wait for client to send all the file contents too.
    file_data = await recv_file_data(handler)
    if file_data is None:
        await send_fail_ack_exit(handler)
        return

    if hashlib.sha256(file_data).digest() != req_ver_msg.file_hash:
        logging.debug("MsgType.REQVERIFICATION: File hash mismatch")
        await send_fail_ack_exit(handler)
        return

    # Find a matching block
    v_blocks = filter(
        lambda blk: blk.fileHash == req_ver_msg.file_hash
        and blk.pubkey == req_ver_msg.pubkey,
        node.chain,
    )
    target_block = next(v_blocks, None)
    found_block = target_block is not None

    if not found_block:
        logging.debug(
            "MsgType.REQVERIFICATION: Cannot find a block for the requested file"
        )
        await send_fail_ack_exit(handler)
    elif not verify_sig_pubkey(
        req_ver_msg.pubkey, target_block.signature, req_ver_msg.file_hash
    ):
        logging.debug("MsgType.REQVERIFICATION: Signature verification failed")
        await send_fail_ack_exit(handler)
    else:
        # Get file contents in 32 byte sizes
        iterations = 50
        pattern_failed = False
        for _ in range(iterations):
            rand_file_ptr = random.randint(0, len(file_data) - 1 - 32)
            block_idx = node.chain.GetBlockIdx(target_block.hdr.hash)
            assert block_idx is not None
            c1 = node.content_db[block_idx].contents[rand_file_ptr : rand_file_ptr + 32]
            c2 = file_data[rand_file_ptr : rand_file_ptr + 32]
            if RabinKarp(c2.hex(), c1.hex()) == -1:
                logging.debug("MsgType.REQVERIFICATION: Pattern matching failed")
                pattern_failed = True

        if not pattern_failed:
            await send_suc_ack_exit(handler)
        else:
            await send_fail_ack_exit(handler)


async def getblockmsg_handle(handler: MsgHandler, node: NetNode):
    logging.debug("Received: msg=MsgType.GETBLOCKMSG, dir=[peer -> node]")
    get_block_msg_bytes = await handler.reader.read(handler.hdr.size)
    getBlockMsg = GetBlocksMsg()
    getBlockMsg = getBlockMsg.Deserialize(handler.hdr.Serialize() + get_block_msg_bytes)
    startIdx = node.chain.GetBlockIdx(getBlockMsg.highestHash)
    endIdx = node.chain.GetBlockIdx(getBlockMsg.stoppingHash)
    if endIdx is None or getBlockMsg.stoppingHash.startswith(b"0" * 32):
        # No stopping limit (get full chain)
        endIdx = len(node.chain) - 1
    if startIdx is None:
        logging.debug(
            "MsgType.GETBLOCKMSG: Cannot determine range ({startIdx}, {endIdx})"
        )
        handler.writer.close()
        return

    if getBlockMsg.highestHash == node.chain.GetLastBlock().hdr.hash:
        logging.debug("MsgType.GETBLOCKMSG: Two nodes have same blockchain, ignore")
    else:
        blocksToSend = []
        for idx, block in enumerate(node.chain):
            if idx > startIdx and idx <= endIdx:
                blocksToSend.append(block)

        # Send an Inv message with all the serialized blocks packed together
        invMsg = InvMsg()
        invMsg.blockCount = len(blocksToSend)
        invMsg.blocks = blocksToSend
        logging.debug(
            f"Sending: msg=MsgType.InvMsg, dir=[node -> peer], blocks={len(blocksToSend)}"
        )
        handler.writer.write(invMsg.Serialize())
        await handler.writer.drain()


async def send_fail_ack_exit(handler: MsgHandler):
    ackMsg = AckMsg()
    ackMsg.status = 13
    handler.writer.write(ackMsg.Serialize())
    await handler.writer.drain()
    handler.writer.close()


async def send_suc_ack_exit(handler: MsgHandler):
    ackMsg = AckMsg()
    ackMsg.status = 12
    handler.writer.write(ackMsg.Serialize())
    await handler.writer.drain()
    handler.writer.close()


async def recv_file_data(handler: MsgHandler) -> bytearray | None:
    # Wait for client to send all the file contents too.
    file_data = bytearray()
    file_recv_bytes = 0
    file_size_bytes = await handler.reader.read(4)
    (file_size,) = struct.unpack(">I", file_size_bytes)
    logging.debug(f"Received: file_len={file_size}")

    while file_recv_bytes != file_size:
        temp_buf = await handler.reader.read(file_size)
        file_recv_bytes += len(temp_buf)
        logging.debug(f"Received: file_progress={file_recv_bytes}/{file_size}")
        file_data.extend(temp_buf)

    logging.debug(f"Received full file: content_len={len(file_data)}")

    # Check if the received contents length matches the expected
    # file size
    if len(file_data) != file_size:
        await send_fail_ack_exit(handler)
        return None
    else:
        return file_data


async def blockdatamsg_handle(handler: MsgHandler, node: NetNode):
    # Received blocks from clients
    logging.debug("Received: msg=MsgType.BLOCKDATAMSG, dir=[client -> node]")
    block_data_msg_bytes = await handler.reader.read(handler.hdr.size)
    bMsg = BlockDataMsg()
    payload = bMsg.Deserialize(handler.hdr.Serialize() + block_data_msg_bytes)
    if not payload.block.IsBlockValid(check_sig=True):
        # Verify the block contents are correct
        logging.debug("Received an invalid block from a client!")
        return

    # Mine the block, add the block to localchain
    payload.block.MineBlock()
    logging.debug(f"Mined block: nonce={payload.block.hdr.nonce}")
    node.chain.AddBlockToChain(payload.block)
    if not node.chain.CheckChainIntegrity(check_sig=True):
        # Remove block from chain
        logging.debug("Chain integrity checks failed")
        node.chain.localChain.pop()
        await send_fail_ack_exit(handler)
        return

    logging.debug(f"Added block: hash={node.chain.GetLastBlock().hdr.hash.hex()}")
    invMsg = InvMsg()
    invMsg.blockCount = 1
    invMsg.blocks.append(node.chain.GetLastBlock())
    # Broadcast block to connected peers if available
    logging.debug(f"Sending: msg=MsgType.InvMsg (Broadcast), peers={len(node.peers)}")
    for peer in node.peers:
        peer.writer.write(invMsg.Serialize())
        await peer.writer.drain()
        logging.debug(
            f"Sending: msg=MsgType.InvMsg, peer={peer.addr}, peer_port={peer.port}"
        )

    file_data = await recv_file_data(handler)
    if file_data is None:
        await send_fail_ack_exit(handler)
        return

    # Put the file contents in some kind of index (storage)
    # where we can retreive it later.
    blk_content = BlockContent()
    blk_content.contents = file_data
    blk_content.hdr = node.chain.GetLastBlock().hdr
    blk_content.file_name = "put_name_here.txt"
    node.content_db.append(blk_content)

    # TODO: Broadcast file contents to other nodes.
    # Only one node containing the file content is not
    # very distributed (Multiple-Source-Truth)
    # In real project file contents should probably encrypted with
    # file owner (client) private key using a symmetric encryption AES

    # Send an ACK to the client to tell that the block has
    # been propagated to all nodes on the network
    await send_suc_ack_exit(handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="node",
        description="""Node program for litedocchain""",
    )
    parser.add_argument("-a", "--addr", help="node server address", default="localhost")
    parser.add_argument("-p", "--port", type=int, help="node server port", default=3333)
    parser.add_argument("--paddr", help="peer address")
    parser.add_argument("--pport", type=int, help="peer port")
    args = parser.parse_args()
    # print(args)

    node = NetNode(args.addr, args.port)
    node.chain.CreateGenesisBlock()
    genesis_content = BlockContent()
    genesis_content.hdr = node.chain.GetGenesisBlock().hdr
    genesis_content.contents = bytearray(b"genesis")
    node.content_db.append(genesis_content)

    logging.debug(f"Genesis: hash={node.chain.GetGenesisBlock().hdr.hash.hex()}")
    serv_thread = threading.Thread(target=node.run_async_server)
    serv_thread.start()

    if args.paddr is None or args.pport is None:
        logging.debug("Cannot connect to any peer, no peer address and port")
    else:
        node.run_async_client(args.paddr, args.pport)

    try:
        serv_thread.join()
    except KeyboardInterrupt:
        logging.info("Shutting down node")
