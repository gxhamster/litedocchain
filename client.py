from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import argparse

def run():
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open("key.pem", "wb") as f:
        f.write(private_bytes)
        
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
        description='Client program to connect to litedocchain network',
    )
    parser.add_argument('-g', '--generate', action='store_true', help='Generate a new private key')
    parser.add_argument('-k', '--keyfile', default='key.pem')
    args = parser.parse_args()
    print(args)
    