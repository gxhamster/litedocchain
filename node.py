from zlib import crc32
from struct import pack, unpack
import json
import socket
import hashlib
import threading
import time


class MessageHeader(object):
    def __init__(self, command: int) -> None:
        self.magic: bytes = b'litedocchain' # 12 bytes (char)
        self.command: int = command         # 02 bytes (short)
        self.size: int = 0                  # 04 bytes (int) Size of the payload. Bitcoin max=32MB
        self.checksum: bytes = b''          # 04 bytes (char) 4 byte sha256 of payload
    
    @staticmethod
    def packHdrFrom(msgHdr) -> bytes:
        return pack('>12sHI4s', msgHdr.magic, msgHdr.command, msgHdr.size, msgHdr.checksum)

    def packHdr(self) -> bytes:
        return pack('>12sHI4s', self.magic, self.command, self.size, self.checksum)
    
    @staticmethod
    def unpackHdrInto(buffer: bytes):
        m, c, s, ch = unpack('>12sHI4s', buffer)
        unpackedHdr = MessageHeader(c)
        unpackedHdr.magic = m
        assert unpackedHdr.magic == b'litedocchain'
        unpackedHdr.size = s
        unpackedHdr.command = c
        unpackedHdr.checksum = ch
        return unpackedHdr
    
    def unpackHdr(self, buffer: bytes):
        unpackedHdr = MessageHeader.unpackHdrInto(buffer)
        self.magic = unpackedHdr.magic
        self.command = unpackedHdr.command
        self.size = unpackedHdr.size
        self.checksum = unpackedHdr.checksum
        return self

    def __repr__(self) -> str:
        return f"MessageHeader({self.__dict__})"

class GetBlocksMsg(MessageHeader):   
    def __init__(self) -> None:
        super().__init__(1)
        self.highestHash: bytes = b''  # 64 bytes
        self.stoppingHash: bytes = b'' # 64 bytes

    def Serialize(self) -> bytes:
        return pack('>64s64s', self.highestHash, self.stoppingHash)
    
    def SerializeFull(self) -> bytes:
        buf = bytearray(self.packHdr())
        buf.extend(self.Serialize())
        return bytes(buf)
    
    def Load(self, buffer: bytes):
        self.unpackHdr(buffer[:22])
        h, s = unpack('>64s64s', buffer[22:])
        self.highestHash = h
        self.stoppingHash = s
        return self
            
    def SetChecksumSize(self) -> None:
        self.checksum = self.CalculateChecksum().encode()
        self.size = len(self.Serialize())

    def CalculateChecksum(self) -> str:
        dataBuf = self.Serialize()
        checksum = hashlib.sha256(dataBuf).hexdigest()[:4]
        return checksum

    
    def __repr__(self) -> str:
        s = []
        for key, val in self.__dict__.items():
            s.append(f"{key}={val}")

        return "{}({})".format(self.__class__.__name__, ", ".join(s))


class NetNode:
    def __init__(self, address: str, port: int = 3333) -> None:
        self.address = address
        self.port = port
        self.peers = []
        self.clients = []
    
    def createServer(self):
        print("Starting server")
        msg = GetBlocksMsg()
        msg.highestHash = hashlib.sha256(b'hello').hexdigest().encode()
        msg.stoppingHash = b'0' * 64
        msg.SetChecksumSize()
        sendData = msg.SerializeFull()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.address, self.port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                while True:
                    data = conn.recv(1024)
                    if not data or data.startswith(b"quit"):
                        break
                    print(data)
                    conn.sendall(sendData)
    
    def createClient(self):
        print("Starting client")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.address, self.port))
            s.sendall(b"Hello, world")
            while True:
                data = s.recv(1024)
                print('Buf: ', data[:12], data[:12] == b'litedocchain')
                if data[:12] == b'litedocchain':
                    hdr = MessageHeader.unpackHdrInto(data[:22])
                    print(hdr)
                    print(data[23:])
                    calcChecksum = hashlib.sha256(data[22:]).hexdigest().encode()[:4]
                    print('Checksum: ', calcChecksum, 'Hdr Checksum: ', hdr.checksum)
                    assert calcChecksum == hdr.checksum

n = NetNode("localhost")
serverThread = threading.Thread(target=n.createServer)
serverThread.start()
time.sleep(1)
n.createClient()

# m = MessageHeader(2)
# m.size = 128
# m.checksum = b'055'
# print(m.packHdr())

# msg = GetBlocksMsg()
# msg.highestHash = hashlib.sha256(b'hello').hexdigest().encode()
# msg.stoppingHash = b'0' * 64
# msg.SetChecksumSize()
# buf = msg.SerializeFull()
# print(buf)
# print(msg.Load(buf))


# print()
