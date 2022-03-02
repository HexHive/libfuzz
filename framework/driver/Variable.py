from . import Value, Type, Address

class Variable(Value):
    token: str
    type: Type

    def __init__(self, token, type):
        self.token  = token
        self.type   = type

        self.addr   = Address.Address(token, self)

    def get_token(self):
        return self.token

    def get_type(self):
        return self.type

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.token})"
    
    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key + type
    def __hash__(self):
        return hash(self.token + str(self.__class__.__name__))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def get_address(self):
        return self.addr