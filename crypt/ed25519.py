from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from typing import cast
from hashlib import sha256

"""
Private key:    32 byte
Public key:     32 byte
"""

DEFAULT_KEY_FILE = "key.pem"


def gen_priv_key(out_key_file: str = DEFAULT_KEY_FILE):
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(out_key_file, "wb") as f:
        f.write(private_bytes)


def import_prv_key_file(file_name: str = DEFAULT_KEY_FILE) -> Ed25519PrivateKey | None:
    try:
        with open(file_name, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
            )
            p: Ed25519PrivateKey = cast(Ed25519PrivateKey, private_key)
            return p
    except FileNotFoundError:
        print(f"The keyfile [{file_name}] does not exist")
    except OSError as error:
        print(f"An error occured while reading {error}")
    return None


def ReadPrivateKeyFromFile() -> Ed25519PrivateKey:
    with open(DEFAULT_KEY_FILE, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )
        p: Ed25519PrivateKey = cast(Ed25519PrivateKey, private_key)
        return p


def compute_file_sig(private_key: Ed25519PrivateKey, filePath: str) -> bytes:
    """Computes the signature for file at filePath using Ed25519.
    Reads all file contents at once and does sha256 on the contents before
    applying signature
    File -> sha256(File) -> sign(sha256(File))
    """
    fileData = b""
    with open(filePath, "rb") as file:
        fileData = file.read()
    hashed = sha256(fileData)
    signature = private_key.sign(hashed.digest())
    return signature


def verify_sig_from_file(
    private_key: Ed25519PrivateKey, signature: bytes, fileData: bytes
) -> bool:
    public_key = private_key.public_key()
    try:
        hashedFileData = sha256(fileData)
        public_key.verify(signature, hashedFileData.digest())
        return True
    except:
        return False


def verify_sig_from_hash(
    private_key: Ed25519PrivateKey, signature: bytes, sha256FileHash: bytes
) -> bool:
    public_key = private_key.public_key()
    try:
        public_key.verify(signature, sha256FileHash)
        return True
    except:
        return False


def verify_sig_pubkey(pubkey: bytes, signature: bytes, sha256FileHash: bytes) -> bool:
    publicKey = Ed25519PublicKey.from_public_bytes(pubkey)
    try:
        publicKey.verify(signature, sha256FileHash)
        return True
    except:
        return False


def compute_file_sig_inc(private_key: Ed25519PrivateKey, filePath: str) -> bytes:
    """Computes signature by incrementally applying sha256 on each read
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
