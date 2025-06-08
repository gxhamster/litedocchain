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
        conflict_handler='resolve'
    )
    sub_parsers = parser.add_subparsers(help='Commands', dest='command')
    generate_cmd_parser = sub_parsers.add_parser('generate', help='generate a new private key')
    generate_cmd_parser.add_argument('-k', '--keyfile', required=False, nargs='?', default=DEFAULT_KEY_FILE)
    shared_parser = argparse.ArgumentParser(add_help=False)
    shared_parser.add_argument('-f', '--file', required=True, help='selected file')
    shared_parser.add_argument('-a', '--addr', required=True, help='litedocchain node address')
    shared_parser.add_argument('-p', '--port', required=True, type=int, help='litedocchain node port')
    shared_parser.add_argument('-k', '--keyfile', required=False, nargs='?', default=DEFAULT_KEY_FILE)
    add_file_cmd_parser = sub_parsers.add_parser('add', help='add a new file to blockchain', parents=[shared_parser])
    verify_cmd_parser = sub_parsers.add_parser('verify', help='verify a file exists in the chain', parents=[shared_parser])
    verify_cmd_parser.add_argument('--pubkey', '-pk', help='public key of the file owner (if not --keyfile)')
    show_cmd_parser = sub_parsers.add_parser('show', help='show key information')
    show_cmd_parser.add_argument('-k', '--keyfile', required=False, nargs='?', default=DEFAULT_KEY_FILE)
    
    args = parser.parse_args()
    # print(args)
    
    if args.command == 'show':
        priv_key = import_prv_key_file(args.keyfile)
        if not priv_key:
            print(f'Cannot import private key file, name={args.keyfile}')
            print('Exiting')
            sys.exit(-1)
        print(f'Public key:  {priv_key.public_key().public_bytes_raw().hex()}')
        print(f'Private key: {priv_key.private_bytes_raw().hex()} (DONT REVEAL!)')
    
    elif args.command == 'generate':
        try:
            gen_priv_key(args.keyfile)
            print(f'Created key file, name={args.keyfile}')
        except OSError as err:
            print(f'Cannot create key file, name={args.keyfile}', err)
    
    elif args.command == 'add':
        priv_key = import_prv_key_file(args.keyfile)
        if not priv_key:
            print(f'Cannot import private key file, name={args.keyfile}')
            print('Exiting')
            sys.exit(-1)
        f_hash, f_sig = None, None
        try:
            f_hash, f_sig = compute_file_sig_hash_pair(priv_key, args.file)
        except FileNotFoundError:
            print(f'Cannot open file={args.file}')
            sys.exit(-1)
        
        print(f'File: {args.file}')
        print(f'File hash:', f_hash.hex())
        print(f'File sign: {f_sig.hex()[:64]}\n{' '*11}{f_sig.hex()[64:]}')
        
        # Connect to node
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
            print(f"Sent block: node={sock.getpeername()[0]}")
            
            print(f"Sending file contents: node={sock.getpeername()[0]}")
            with open(args.file, 'rb') as file:
                file_size = struct.pack('>I', os.stat(args.file).st_size)
                sock.send(file_size)
                sent = sock.sendfile(file)
                print(f'Sent {sent} bytes')
        
            hdr_bytes = sock.recv(MsgHdr.struct.size)
            block_created = False
            if hdr_bytes.startswith(MAGIC_HDR_VALUE):
                hdr = MsgHdr()
                hdr = hdr.Deserialize(hdr_bytes)
                if hdr.command == MsgType.ACK:
                    ack_msg_bytes = sock.recv(hdr.size)
                    ackMsg = AckMsg()
                    ackMsg.Deserialize(hdr_bytes + ack_msg_bytes)
                    if ackMsg.status == 12:
                        print(f"Block created successfully on the network")
                        block_created = True
                    elif ackMsg.status == 13:
                        block_created = False
            if not block_created:
                print("Something went wrong, could not create the block")
            sock.close()
            
    elif args.command == 'verify':
        f_hash, f_pubkey = None, None
        if args.pubkey and len(args.pubkey) == 64:
            f_hash = compute_file_hash(args.file)
            f_pubkey = bytes.fromhex(args.pubkey)
        else:
            priv_key = import_prv_key_file(args.keyfile)
            if not priv_key:
                print(f'Cannot import key file, name={args.keyfile}')
                print('Exiting')
                sys.exit(-1)

            try:
                f_hash = compute_file_hash(args.file)
                f_pubkey =  priv_key.public_key().public_bytes_raw()  
            except FileNotFoundError:
                print(f'Cannot open file={args.file}')
                sys.exit(-1)
        
        print(f'File: {args.file}')
        print(f'File hash:', f_hash.hex())
        print(f'PublicKey:', f_pubkey.hex())
            
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
            
            # Send ReqVerificationMsg
            req_ver_msg = ReqVerificationMsg()
            req_ver_msg.file_hash = f_hash    
            req_ver_msg.pubkey = f_pubkey          
            sock.sendall(req_ver_msg.Serialize())
            
            # Send file
            with open(args.file, 'rb') as file:
                file_size = struct.pack('>I', os.stat(args.file).st_size)
                sock.send(file_size)
                sent = sock.sendfile(file)
                print(f'Sent {sent} bytes')
            
            # Wait for answer from node
            hdr_bytes = sock.recv(MsgHdr.struct.size)
            block_created = False
            if hdr_bytes.startswith(MAGIC_HDR_VALUE):
                hdr = MsgHdr()
                hdr = hdr.Deserialize(hdr_bytes)
                if hdr.command == MsgType.ACK:
                    ack_msg_bytes = sock.recv(hdr.size)
                    ackMsg = AckMsg()
                    ackMsg.Deserialize(hdr_bytes + ack_msg_bytes)
                    if ackMsg.status == 12:
                        print(f"File verification successful")
                        block_created = True
                    elif ackMsg.status == 13:
                        block_created = False
            if not block_created:
                print("File verification failed")
            sock.close()
        
    else:
        print('Unrecognized command')
        sys.exit(-1)
    