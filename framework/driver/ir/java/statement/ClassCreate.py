from typing import List
from driver.ir.java.type import ClassType, JavaType
from . import MethodCall

# This statement is used to generate sentence such as "A a = new A(p1, p2, ...)"
# class_var in this statement represents the created instance "a"
class ClassCreate(MethodCall):
    def __init__(self, declaring_class: ClassType, arg_types: List[JavaType], is_static: bool=False):
        super().__init__(declaring_class, arg_types)
        self.is_static = is_static
        
    def __hash__(self):
        return hash((self.__class__.__name__, super().__hash__()))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.declaring_class.className})"
