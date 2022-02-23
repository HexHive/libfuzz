from abc import ABC, abstractmethod

class Element(ABC):
    def __init__(self, name):
        self.name = name

    # for an element, the hash is just the key
    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.name})"