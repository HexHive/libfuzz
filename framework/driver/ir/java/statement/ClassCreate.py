from typing import List
from driver.ir.java.type import ClassType, JavaType, ParameterizedType
from . import MethodCall

# This statement is used to generate sentence such as "A a = new A(p1, p2, ...)"
# class_var in this statement represents the created instance "a"
class ClassCreate(MethodCall):
    def __init__(self, declaring_class: JavaType, arg_types: List[JavaType], exceptions: List[ClassType], is_static: bool=False):
        super().__init__(declaring_class, declaring_class, arg_types, exceptions)
        self.is_static = is_static

        self.next_fulfill_pos = 0
        
    def get_all_type(self) -> List[JavaType]:
        return self.arg_types

    def copy(self):
        return ClassCreate(self.declaring_class, self.arg_types, self.exceptions, self.is_static)

    def __hash__(self):
        return hash((self.__class__.__name__, super().__hash__()))

    def __str__(self):
        if isinstance(self.declaring_class, ParameterizedType):
            return f"{self.__class__.__name__}(name={self.declaring_class.rawType.className},args=[" + ",".join([x.className for x in self.declaring_class.argType]) + "])"
        elif isinstance(self.declaring_class, ClassType):
            return f"{self.__class__.__name__}(name={self.declaring_class.className})"
        else:
            raise Exception("ClassCreate does not support other type")
