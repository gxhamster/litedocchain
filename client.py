from crypt.ed25519 import *
import argparse
                    
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
    args = parser.parse_args()
    print(args)
    # if args.keyfile is None or args.keyfile == DEFAULT_KEY_FILE:
    #     run()
    priv_key = ReadPrivateKeyFromFile()
    sig1 = FileSig(priv_key, args.file)
    sig2 = FileSigInc(priv_key, args.file)
    print(len(sig1))
    print(sig2)
    
    with open(args.file, 'rb') as file:
        data = file.read()
        print(VerifySig(priv_key, sig1, data))
    