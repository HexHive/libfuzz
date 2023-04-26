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
            self.token = f"{type.rawType.className}_d{type.dimension}_{cnt}"
        elif isinstance(type, ClassType):
            self.token = f"{type.className}_{cnt}"
        elif isinstance(type, ParameterizedType):
            self.token = f"{type.rawType.className}_" + "_".join([x.className for x in type.argType]) + f"_{cnt}"
        else:
            raise Exception("Unsupported type")