from typing import Dict
from driver.ir.java.type import *


class Variable:
    type_count: Dict[JavaType, int] = {}

    def __init__(self, type: JavaType):
        self.type = type

        if not type in Variable.type_count:
            Variable.type_count[type] = 0
        cnt = Variable.type_count[type]
        Variable.type_count[type] += 1

        if isinstance(type, ArrayType):
            self.token = f"{Variable.normalize_classname(type.rawType.className)}_d{type.dimension}_{cnt}"
        elif isinstance(type, ClassType):
            self.token = f"{Variable.normalize_classname(type.className)}_{cnt}"
        elif isinstance(type, ParameterizedType):
            self.token = f"{Variable.normalize_classname(type.rawType.className)}_" + "_".join([Variable.normalize_classname(x.className) for x in type.argType]) + f"_{cnt}"
        else:
            raise Exception("Unsupported type")
        
    def __eq__(self, __value: object) -> bool:
        if not isinstance(__value, Variable):
            return False
        return self.token == __value.token
    
    def __hash__(self) -> int:
        return hash(self.token)
        
    @staticmethod
    def normalize_classname(className: str):
        name = className.split(".")[-1]
        return name.lower()