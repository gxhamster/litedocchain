from crypt.ed25519 import *
from net.message import BlockDataMsg, VersionMsg, VersionConnType
from primitives.block import Block
from hashlib import sha256
import argparse
import socket
                    
def run():
    private_key = ReadPrivateKeyFromFile()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    print("Bytes: ", private_bytes)
    hexprivate = private_bytes.hex()
    print("Bytes (hex): ", hexprivate)
    print("Bytes: ", bytes.fromhex(hexprivate))

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    print(public_bytes)
    print(public_bytes.hex())

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='client',
        description="""Client program to connect to litedocchain network""",
    )
    parser.add_argument('-g', '--generate', action='store_true', help='generate a new private key')
    parser.add_argument('-k', '--keyfile', required=False, nargs='?', default=DEFAULT_KEY_FILE)
    parser.add_argument('-f', '--file', help='file to store on chain')
    parser.add_argument('-a', '--addr', help='litedocchain node address')
    parser.add_argument('-p', '--port', type=int, help='litedocchain node port')
    parser.add_argument('--verify', action='store_true', help='verify a file exists in the chain')
    args = parser.parse_args()
    print(args)
    if args.verify:
        raise NotImplementedError("Verifcation is not yet implemented")
    
    priv_key = ReadPrivateKeyFromFile()
    sig2 = FileSigInc(priv_key, args.file)
    
    fileHash = b''
    with open(args.file, 'rb') as file:
        data = file.read()
        VerifySig(priv_key, sig2, data)
        fileHash = sha256(data).digest()
    
    if args.addr and args.port:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((args.addr, args.port))
            
            verMsg = VersionMsg()
            verMsg.connType = VersionConnType.CLIENT
            verMsg.connAddr = socket.inet_aton(sock.getsockname()[0])
            verMsg.connPort = sock.getsockname()[1]
            sock.sendall(verMsg.Serialize())
            
            print(f"Connected to: node_addr={sock.getpeername()[0]}, node_port={sock.getpeername()[1]}")
            block = Block()
            block.pubkey = priv_key.public_key().public_bytes_raw()
            block.signature = sig2
            block.fileHash = fileHash
            block.hdr.hash =  block.hdr.CalculateHash(block.signature + block.fileHash + block.pubkey)
            if not block.IsBlockValid(check_sig=True):
                raise AssertionError("Block is not valid")
            
            msg = BlockDataMsg()
            msg.block = block
            msg.hdr.checksum = msg.CalculateChecksum()
            msg.hdr.size = len(msg.block.Serialize())
            
            sock.sendall(msg.Serialize())
            print(f"Sending: file='{args.file}', node={sock.getpeername()[0]}")
            data = sock.recv(1024)
            # TODO: Should wait for some kind of ACK from the node on
            # what happened to the block sent.
            
            sock.close()
        