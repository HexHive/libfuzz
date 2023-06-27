from enum import Enum

class TypeTag(Enum):
    PRIMITIVE = 1
    STRUCT = 2

class Type:
    token: str
    size: int
    # attributes!
    is_incomplete: bool
    is_const: bool
    tag: TypeTag

    string_types = ["char*", "unsigned char*", "wchar_t*", \
                    "char**", "unsigned char**", "wchar_t**"]

    size_types = ["size_t", "int", "uint32_t", "uint64_t"]
    
    
    def __init__(self, token, size = 0, is_incomplete = False, is_const = False, tag = TypeTag.PRIMITIVE):
        self.token          = token
        self.size           = size
        self.is_incomplete  = is_incomplete
        self.is_const       = is_const
        self.tag            = tag

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.token})"
    
    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key
    def __hash__(self):
        return hash(self.token + str(self.__class__.__name__) + str(self.is_const))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def get_size(self):
        return self.size

    def get_token(self):
        return self.token