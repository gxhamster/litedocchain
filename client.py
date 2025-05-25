from crypt.ed25519 import *
from net.message import *
from primitives.block import Block
import argparse
import socket
import sys
import struct
import os
                    
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
    parser.add_argument('--list-blocks', action='store_true', help='list blocks owned by me')
    args = parser.parse_args()
    # print(args)

    keyfile_name = ''
    if not args.keyfile:
        keyfile_name = DEFAULT_KEY_FILE
    else:
        keyfile_name = args.keyfile 
    
    if args.generate:
        try:
            gen_priv_key(keyfile_name)
            print(f'Created key file, name={keyfile_name}')
        except OSError as err:
            print(f'Cannot create key file, name={keyfile_name}', err)
        
    priv_key = import_prv_key_file(keyfile_name)
    if not priv_key:
        print(f'Cannot import private key file, name={keyfile_name}')
        print('Exiting')
        sys.exit(-1)
    
    if args.list_blocks:
       raise NotImplementedError('--list-blocks') 
        
    if args.file:
        f_hash, f_sig = compute_file_sig_hash_pair(priv_key, args.file)

        print(f'File hash:', f_hash.hex())
        print(f'File sign: {f_sig.hex()[:64]}\n{' '*11}{f_sig.hex()[64:]}')
        
        if args.addr and args.port:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.connect((args.addr, args.port))
                except:
                    print(f'Cannot connect to node: addr={args.addr}, port={args.port}')
                    print('Exiting')
                    sys.exit(-1)
                    
                verMsg = VersionMsg()
                verMsg.connType = VersionConnType.CLIENT
                verMsg.connAddr = socket.inet_aton(sock.getsockname()[0])
                verMsg.connPort = sock.getsockname()[1]
                sock.sendall(verMsg.Serialize())
                print(f"Connected to: node_addr={sock.getpeername()[0]}, node_port={sock.getpeername()[1]}")
                
                if args.verify:
                    # Verify that a file you have actually belongs to you        
                    raise NotImplementedError("Verifcation is not yet implemented")
                else:
                    # Send to create a new block
                    block = Block()
                    block.pubkey = priv_key.public_key().public_bytes_raw()
                    block.signature = f_sig
                    block.fileHash = f_hash
                    block.hdr.hash =  block.hdr.CalculateHash(block.signature + block.fileHash + block.pubkey)
                    if not block.IsBlockValid(check_sig=True):
                        raise AssertionError("Block is not valid")
                    
                    
                    block_msg = BlockDataMsg()
                    block_msg.block = block
                    block_msg.hdr.checksum = block_msg.CalculateChecksum()
                    block_msg.hdr.size = len(block_msg.block.Serialize())
                    sock.sendall(block_msg.Serialize())
                    print(f"Sent block: file='{args.file}', node={sock.getpeername()[0]}")
                    
                    
                    print(f"Sending file contents: file='{args.file}', node={sock.getpeername()[0]}")
                    with open(args.file, 'rb') as file:
                        file_size = struct.pack('>I', os.stat(args.file).st_size)
                        sock.send(file_size)
                        sent = sock.sendfile(file)
                        print(f'Sent {sent} bytes')
                
                    data = sock.recv(1024)
                    block_created = False
                    if data.startswith(MAGIC_HDR_VALUE):
                        hdrSize = MsgHdr.struct.size
                        hdr = MsgHdr()
                        hdr = hdr.Deserialize(data[:hdrSize])
                        if hdr.command == MsgType.ACK:
                            ackMsg = AckMsg()
                            ackMsg.Deserialize(data)
                            if ackMsg.status == 12:
                                print(f"Block created successfully on the network")
                                block_created = True
                            elif ackMsg.status == 13:
                                block_created = False
                    if not block_created:
                        print("Something went wrong, could not create the block")
                    sock.close()
        