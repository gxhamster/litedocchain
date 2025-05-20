from abc import ABC, abstractmethod
from typing import Self

class Serializable(ABC):
    """ This class should be inherited by all the classes which
    implement a message protocol that will be send on the blockchain
    network.
    
    struct: (Struct) Defines the binary format of the message, not header
    (Not recommended to call the .pack method of struct, call serialize)
    """
    struct = None 
    def __init__(self) -> None:
        pass

    @abstractmethod
    def Serialize(self) -> bytes:
        raise NotImplementedError("Need to implement Serialize")

    @abstractmethod
    def Deserialize(self, buffer: bytes) -> Self:
        raise NotImplementedError("Need to implement Deserialize")
