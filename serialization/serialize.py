from abc import ABC, abstractmethod
from typing import Self

class Serializable(ABC):
    """ This class should be inherited by all the classes which
    implement a message protocol that will be send on the blockchain
    network.
    
    struct: (Struct) Defines the binary format of the message, not header
    """
    struct = None 
    def __init__(self) -> None:
        if self.struct is None:
            raise TypeError("A derived class of Serializable must have struct")

    @abstractmethod
    def Serialize(self) -> bytes:
        pass

    @abstractmethod
    def Deserialize(self, buffer: bytes) -> Self:
        pass
