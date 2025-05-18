from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typing import cast
from hashlib import sha256
import argparse

DEFAULT_KEY_FILE="key.pem"
def GeneratePrivateKey():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(DEFAULT_KEY_FILE, "wb") as f:
        f.write(private_bytes)

def ReadPrivateKeyFromFile() -> Ed25519PrivateKey:
    with open(DEFAULT_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        p: Ed25519PrivateKey =  cast(Ed25519PrivateKey, private_key)
        return p

def FileSig(private_key: Ed25519PrivateKey, filePath: str) -> bytes:
    """ Computes the signature for file at filePath using Ed25519.
    Reads all file contents at once and does sha256 on the contents before
    applying signature
    File -> sha256(File) -> sign(sha256(File))
    """
    fileData = b''
    with open(filePath, 'rb') as file:
        fileData = file.read()
    hashed = sha256(fileData)
    signature = private_key.sign(hashed.digest())
    return signature

def VerifySig(private_key: Ed25519PrivateKey, signature: bytes, fileData: bytes) -> bool:
        public_key = private_key.public_key()
        try:
            hashedFileData = sha256(fileData)
            public_key.verify(signature, hashedFileData.digest())
            return True
        except:
            return False
        
def FileSigInc(private_key: Ed25519PrivateKey, filePath: str) -> bytes:
    """ Computes signature by incrementally applying sha256 on each read
    on a buffered reader. Preffered for larger file (above 4MB).
    """
    with open(filePath, 'rb') as reader:
        bufSize = 1024
        sha256hasher = sha256()
        while True:
            data = reader.read(bufSize)
            sha256hasher.update(data)
            if data == b'':
                break
        signature = private_key.sign(sha256hasher.digest())
        return signature
                    
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
    