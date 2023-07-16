from typing import List

from driver.ir.java.type import JavaType, ClassType
from . import MethodCall

class ApiInvoke(MethodCall):
    def __init__(self, function_name: str, declaring_class: ClassType, return_type: JavaType, arg_types: List[JavaType], exceptions: List[ClassType], is_static: bool):
        super().__init__(declaring_class, return_type, arg_types, exceptions)
        self.function_name = function_name
        self.is_static = is_static

        if self.is_static:
            self.next_fulfill_pos = 0

    def get_all_type(self) -> List[JavaType]:
        if self.is_static:
            return self.arg_types
        return [self.declaring_class] + self.arg_types

    def copy(self):
        return ApiInvoke(self.function_name, self.declaring_class, self.ret_type, self.arg_types, self.exceptions, self.is_static)

    def __hash__(self):
        arg_lst = [super().__hash__()]
        arg_lst += [self.__class__.__name__]
        arg_lst += [self.function_name]
        arg_lst += [self.is_static]
        return hash(tuple(arg_lst))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.declaring_class.className}.{self.function_name})"