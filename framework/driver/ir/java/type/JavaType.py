from abc import ABC, abstractmethod
from typing import Dict, Set

from driver.ir.java.variable import Variable

class JavaType(ABC):

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def __hash__(self):
        pass

    @abstractmethod
    def __str__(self):
        pass
    
    def __repr__(self):
        return str(self)

    def __eq__(self, other):
        return hash(self) == hash(other)

    # when type is a subtype or the same type, return true.
    @abstractmethod
    def has_subtype(self, type: 'JavaType') -> bool:
        pass

    def check_type_compatible(self, var: Variable) -> bool:
        return self.has_subtype(var.type)