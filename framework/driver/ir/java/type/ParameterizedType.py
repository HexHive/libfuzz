from typing import Dict, List, Set, Tuple

from . import JavaType, ClassType

class ParameterizedType(JavaType):
    def __init__(self, rawType: str, argType: List[str], subtypes: Dict[Tuple[str, str], Set[str]]):
        self.rawType = ClassType(rawType, subtypes, False)
        self.argType = [ClassType(arg, subtypes, not "." in arg) for arg in argType]
        self.subtypes = subtypes.get((rawType, str(argType)))
    
    def has_subtype(self, type: JavaType) -> bool:
        if isinstance(type, ClassType) and type.className in self.subtypes:
            return True
        if not isinstance(type, ParameterizedType):
            return False
        if not self.rawType.has_subtype(type.rawType):
            return False
        if len(self.argType) != len(type.argType):
            return False
        for i, t in enumerate(self.argType):
            if t != type.argType[i]:
                return False
        return True
    
    def __str__(self):
        return f"{self.__class__.__name__}(type={self.rawType})"
    
    def __hash__(self):
        arg_lst = [self.__class__.__name__]
        arg_lst += [self.rawType]
        arg_lst += [hash(a) for a in self.argType]
        return hash(tuple(arg_lst))
