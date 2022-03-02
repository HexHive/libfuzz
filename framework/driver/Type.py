from abc import abstractmethod

class Type:
    token: str
    size: int
    def __init__(self, token, size = 0):
        self.token  = token
        self.size   = size

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.token})"
    
    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key
    def __hash__(self):
        return hash(self.token + str(self.__class__.__name__))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def get_size(self):
        return self.size