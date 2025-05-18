from struct import Struct
import socket
import hashlib
import threading
import time
from serialization.serialize import Serializable
from primitives.block import *
from primitives.chain import *

class MessageHeader(Serializable):
    """ Every message sent on the blockchain network will have a header
    with the metadata of the payload. Command field will be used to identify
    which type of packet and which decoder to use.
    """
    struct = Struct('>12sHI4s')
    CHECKSUM_LEN = 4
    def __init__(self, command: int = 0) -> None:
        super().__init__()
        self.magic: bytes = b'litedocchain' # 12 bytes (char)
        self.command: int = command         # 02 bytes (short)
        self.size: int = 0                  # 04 bytes (int) Size of the payload. Bitcoin max=32MB
        self.checksum: bytes = b''          # 04 bytes (char) 4 byte sha256 of payload
            
    def Serialize(self) -> bytes:
        return self.struct.pack(self.magic, self.command, self.size, self.checksum)

    def Deserialize(self, buffer: bytes):
        m, c, s, ch  = self.struct.unpack(buffer)
        self.magic = m
        assert self.magic == b'litedocchain'
        self.command = c
        self.size = s
        self.checksum = ch
        return self

    def __repr__(self) -> str:
        return f"""MessageHeader(
    magic={self.magic},
    command={self.command},
    size={self.size},
    checksum={self.checksum})"""

class GetBlocksMsg(Serializable):
    struct = Struct('>32s32s')   
    def __init__(self) -> None:
        super().__init__()
        self.hdr: MessageHeader = MessageHeader(1)
        self.highestHash: bytes = b''  # 64 bytes
        self.stoppingHash: bytes = b'' # 64 bytes
    
    def Serialize(self) -> bytes:
        return self.hdr.Serialize() + self.struct.pack(self.highestHash, self.stoppingHash)
    
    def Deserialize(self, buffer: bytes):
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        h, s = self.struct.unpack(buffer[hdrSize:])
        self.highestHash = h
        self.stoppingHash = s
        return self
            
    def SetChecksumSize(self) -> None:
        self.hdr.checksum = self.CalculateChecksum()
        self.hdr.size = len(self.struct.pack(self.highestHash, self.stoppingHash))

    def CalculateChecksum(self) -> bytes:
        dataBuf = self.struct.pack(self.highestHash, self.stoppingHash)
        checksum = hashlib.sha256(dataBuf).digest()[:MessageHeader.CHECKSUM_LEN]
        return checksum

    
    def __repr__(self) -> str:
        return f"""GetBlocksMsg(
    {self.hdr},
    highestHash={self.highestHash},
    stoppingHash={self.stoppingHash})"""


class NetNode:
    def __init__(self, address: str, port: int = 3333) -> None:
        self.address = address
        self.port = port
        self.peers = []
        self.clients = []
        self.chain = Chain()
        self.chain.CreateGenesisBlock()
    
    def createServer(self):
        print("Starting server")
        msg = GetBlocksMsg()
        msg.highestHash = hashlib.sha256(b'hello').digest()
        msg.stoppingHash = b'0' * 32
        msg.SetChecksumSize()
        sendData = msg.Serialize()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.address, self.port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if data == b'':
                        break
                    print(data)
    
    def createClient(self):
        print("Starting client")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.address, self.port))
            s.sendall(b"Hello, world")
            while True:
                data = s.recv(1024)
                if data == b'':
                    break
                print(data)

if __name__ == "__main__":
    n = NetNode("localhost")
    b1 = Block()
    n.chain.localChain.append(Block())

    serverThread = threading.Thread(target=n.createServer)
    serverThread.start()
    time.sleep(1)
    n.createClient()


