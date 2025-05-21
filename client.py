from crypt.ed25519 import *
from net.message import BlockDataMsg, VersionMsg, VersionConnType, MAGIC_HDR_VALUE, AckMsg, MsgType, MsgHdr
from primitives.block import Block
from hashlib import sha256
import argparse
import socket
import sys
                    
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
    # print(args)
    if args.verify:
        raise NotImplementedError("Verifcation is not yet implemented")
    
    keyfile_name = ''
    if not args.keyfile:
        keyfile_name = DEFAULT_KEY_FILE
    else:
        keyfile_name = args.keyfile 
    
    if args.generate:
        try:
            gen_priv_key(args.keyfile)
            print(f'Created key file, name={keyfile_name}')
        except OSError as err:
            print(f'Cannot create key file, name={keyfile_name}', err)
        
    priv_key = import_prv_key_file(args.keyfile)
    if not priv_key:
        print(f'Cannot import private key file, name={keyfile_name}')
        sys.exit(-1)
    
    if args.file:
        file_sig = compute_file_sig_inc(priv_key, args.file)
        fileHash = b''
        with open(args.file, 'rb') as file:
            data = file.read()
            verify_sig_from_file(priv_key, file_sig, data)
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
                block.signature = file_sig
                block.fileHash = fileHash
                block.hdr.hash =  block.hdr.CalculateHash(block.signature + block.fileHash + block.pubkey)
                if not block.IsBlockValid(check_sig=True):
                    raise AssertionError("Block is not valid")
                
                
                block_msg = BlockDataMsg()
                block_msg.block = block
                block_msg.hdr.checksum = block_msg.CalculateChecksum()
                block_msg.hdr.size = len(block_msg.block.Serialize())
                sock.sendall(block_msg.Serialize())
                
                print(f"Sending: file='{args.file}', node={sock.getpeername()[0]}")
                data = sock.recv(1024)
                block_created = False
                if data.startswith(MAGIC_HDR_VALUE):
                    hdrSize = MsgHdr.struct.size
                    hdr = MsgHdr()
                    hdr = hdr.Deserialize(data[:hdrSize])
                    if hdr.command == MsgType.ACK:
                        ackMsg = AckMsg()
                        ackMsg.Deserialize(data)
                        if ackMsg.nonce == 12:
                            print(f"Block created successfully on the network")
                            block_created = True
                if not block_created:
                    print("Something went wrong, could not create the block")
                sock.close()
        