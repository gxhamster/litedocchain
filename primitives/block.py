import hashlib
from io import BytesIO
from typing import Self
from struct import Struct
from serialization.serialize import Serializable
from crypt.ed25519 import verify_sig_pubkey

VERSION = 1


class BlockHeader(Serializable):
    struct = Struct(">Bd32s32sI")

    def __init__(self):
        self.SetNull()

    def SetNull(self):
        super().__init__()
        self.version = VERSION          # 1 byte char
        self.time: float = 0            # 8 byte double
        self.hashPrevBlock: bytes = b"" # 32 byte string
        self.hash: bytes = b""          # 32 byte string
        self.nonce: int = 0             # 4 byte integer

    def Serialize(self) -> bytes:
        return self.struct.pack(
            self.version, self.time, self.hashPrevBlock, self.hash, self.nonce
        )

    def Deserialize(self, buffer: bytes) -> Self:
        v, t, hp, h, n = self.struct.unpack(buffer)
        self.version = v
        self.time = t
        self.hashPrevBlock = hp
        self.hash = h
        self.nonce = n
        return self

    # Calculate the hash for all the block contents (header contents except the hash)
    def CalculateHash(self, blockData: bytes = b"") -> bytes:
        buffer = bytearray()
        packStructNoHash = Struct(">Bd32sI")
        packedBytes = packStructNoHash.pack(
            self.version, self.time, self.hashPrevBlock, self.nonce
        )
        buffer.extend(packedBytes)
        if blockData != b"":
            buffer.extend(blockData)
        return hashlib.sha256(buffer).digest()

    def __repr__(self):
        return f"""BlockHeader(version={self.version}, time={self.time}, prev={self.hashPrevBlock}, hash={self.hash}, nonce={self.nonce})"""

# BLK_DIFFICULTY determines how many zeros need to be matched
# to be considered a valid block by the PoW algorithm. As the 
# difficulty increases it will take more time. By default, it 
# needs to match 2 bytes
BLK_DIFFICULTY=2
class Block(Serializable):
    """For simplicty in this project, we will consider one document
    to be in a seperate block. This blockchain will have no concept of
    multiple transactions where multiple documents are combined into a single block.
    This would have increase storage requirements of each node in the future.
    The mining frequency will also might overload the network in the future.
    """

    struct = Struct(">64s32s32s")

    def __init__(self) -> None:
        super().__init__()
        self.hdr = BlockHeader()
        self.signature: bytes = b"" # 64 byte Ed25519 signature of fileHash
        self.fileHash: bytes = b""  # 32 byte sha256 of file data
        self.pubkey: bytes = b""    # 32 byte pubkey of private/public key pair of file owner
    

    def Serialize(self) -> bytes:
        hdrBytes = self.hdr.Serialize()
        fieldBytes = self.struct.pack(self.signature, self.fileHash, self.pubkey)
        return hdrBytes + fieldBytes

    def Deserialize(self, buffer: bytes) -> Self:
        hdrSize = self.hdr.struct.size
        self.hdr = self.hdr.Deserialize(buffer[:hdrSize])
        sigBytes, fHash, pKey = self.struct.unpack(buffer[hdrSize:])
        self.signature, self.fileHash, self.pubkey = sigBytes, fHash, pKey
        return self

    def MineBlock(self) -> bytes:
        """Find a nonce value that gives us a hash of some pattern.
        Bitcoin accepts a hash starting with 10 zeros (could be more).
        We will use a pattern that gives 3 zeros just to make it faster.
        Also sets the new hash to the block. Uses a PoW algorithm
        """
        tempHash = self.hdr.CalculateHash(self.signature + self.fileHash + self.pubkey)
        difficulty = BLK_DIFFICULTY
        while not tempHash.startswith(b"\x00" * difficulty):
            self.hdr.nonce += 1
            tempHash = self.hdr.CalculateHash(
                self.signature + self.fileHash + self.pubkey
            )
        self.hdr.hash = tempHash
        return self.hdr.hash

    def IsBlockValid(self, check_sig=False) -> bool:
        """ Checks whether the hash of the block stored in the hdr
        is the same as the calculated hash. Can also verify the signature of the provided
        contents.
        """
        if self.hdr.hash != self.hdr.CalculateHash(
            self.signature + self.fileHash + self.pubkey
        ):
            return False
        if check_sig:
            if not verify_sig_pubkey(self.pubkey, self.signature, self.fileHash):
                return False
        return True

    def __repr__(self) -> str:
        return f"""Block({self.hdr}, signature={self.signature}, fileHash={self.fileHash}, pubkey={self.pubkey})"""

class BlockContent():
    """ A storage structure to hold the contents of the file which the block has a 
    signature on file hash of.
    """
    def __init__(self) -> None:
        self.hdr: BlockHeader = BlockHeader()
        self.file_name: str = '' # We might need file name (ext) on platforms that require it for encoding (Windows)
        self.contents: bytearray = bytearray()
        
class BlockContentDB():
    def __init__(self) -> None:
        self.db: list[BlockContent] = []
        
    def __len__(self):
        return self.db.__len__()
    
    def __getitem__(self, idx):
        return self.db.__getitem__(idx)
    
    def __setitem__(self, idx, val):
        self.db.__setitem__(idx, val)
        
    def append(self, blk_content: BlockContent):
        self.db.append(blk_content)
        
        
def RabinKarp(search_str: str, pattern: str) -> int:
    """ Returns index of start of found pattern if found, otherwise returns -1
    Since I am just going to be using this to match hex as strings I dont think we need
    to add a modulo restriction. base = 16 for hex
    """
    if pattern == '':
        return -1
    base = 16
    h_pattern = 0
    # Compute hash for pattern
    for i in range(len(pattern)):
        h_pattern += ord(pattern[i]) * pow(base, len(pattern) - i - 1)
    
    # Compute hash for substring
    for i in range(len(search_str) - len(pattern) + 1):
        sub_str = search_str[i:i+len(pattern)]
        h_sub = 0
        for k in range(len(sub_str)):
            h_sub += ord(sub_str[k]) * pow(base, len(pattern) - k - 1)
        
        if h_sub == h_pattern:
            # Compare individually
            if sub_str == pattern:
                return i
            
    return -1

    
    