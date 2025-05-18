import socket
import hashlib
import threading
import time
from primitives.block import Block
from primitives.chain import Chain
from net.message import GetBlocksMsg

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
            print(conn, addr)
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
    # n.createClient()


