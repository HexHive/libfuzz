from typing import Dict, Set
from . import JavaType

class ClassType(JavaType):
    def __init__(self, className: str, subtypes: Dict[str, Set[str]], is_primitive: bool):
        self.className = className
        # For convenience, we let classType with an empty package name has a '.' in the beginning. We need to remove this here.
        if className[0] == ".":
            self.className = className[1:]
        self.is_primitive = is_primitive
        
        if is_primitive:
            self.subtypes = []
        else:
            self.subtypes = subtypes.get(className)

    def has_subtype(self, type: JavaType) -> bool:
        if not isinstance(type, ClassType):
            return False
        if self.className == type.className:
            return True
        return type.className in self.subtypes
    
    def __str__(self):
        return f"{self.__class__.__name__}(name={self.className})"
    
    def __hash__(self):
        return hash(self.__class__.__name__ + self.className)