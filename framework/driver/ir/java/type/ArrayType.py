from typing import Dict, Set, Tuple

from . import JavaType, ClassType

import re

class ArrayType(JavaType):
    def __init__(self, className: str, subtypes: Dict[Tuple[str, str], Set[str]]):
        if not className.startswith("["):
            raise Exception("Not an ArrayType")
        
        pattern = re.compile("\[*")
        idx = re.search(pattern, className).end()
        self.dimension = idx

        sig = className[idx] # Java Type Signature
        if sig == "Z":
            self.rawType = ClassType("boolean", subtypes, True)
        elif sig == "B":
            self.rawType = ClassType("byte", subtypes, True)
        elif sig == "C":
            self.rawType = ClassType("char", subtypes, True)
        elif sig == "S":
            self.rawType = ClassType("short", subtypes, True)
        elif sig == "I":
            self.rawType = ClassType("int", subtypes, True)
        elif sig == "J":
            self.rawType = ClassType("long", subtypes, True)
        elif sig == "F":
            self.rawType = ClassType("float", subtypes, True)
        elif sig == "D":
            self.rawType = ClassType("double", subtypes, True)
        elif sig == "L":
            assert className[-1] == ";"
            self.rawType = ClassType(className[idx + 1 : -1], subtypes, False)
        else:
            raise Exception("Malformed className")
    
    def has_subtype(self, type: JavaType) -> bool:
        if not isinstance(type, ArrayType):
            return False
        if type.dimension != self.dimension:
            return False
        return self.rawType.has_subtype(type.rawType)
    
    def __str__(self):
        return f"{self.__class__.__name__}(name={self.rawType.className},dimension={self.dimension})"
    
    def __hash__(self):
        return hash(self.__class__.__name__ + str(self.dimension) + str(hash(self.rawType)))
