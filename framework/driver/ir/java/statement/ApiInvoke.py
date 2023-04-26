from typing import List

from driver.ir.java.type import JavaType, ClassType
from driver.ir.java.variable import Variable
from . import MethodCall

# This statement is used to generate sentence like "m = x.method(param...)"
# class_var in this statement represents the argument "x"
class ApiInvoke(MethodCall):
    def __init__(self, function_name: str, declaring_class: ClassType, return_type: JavaType, arg_types: List[JavaType], is_static: bool):
        super().__init__(declaring_class, arg_types)
        self.function_name = function_name
        self.return_type = return_type
        self.is_static = is_static

        self.ret_var = None

    def set_ret_var(self, ret_var: Variable):

        assert self.return_type.has_subtype(ret_var.type)

        self.ret_var = ret_var

    def __hash__(self):
        arg_lst = [super().__hash__()]
        arg_lst += [self.__class__.__name__]
        arg_lst += [self.function_name]
        arg_lst += [self.is_static]
        arg_lst += [hash(self.return_type)]
        return hash(tuple(arg_lst))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.declaring_class.className}.{self.function_name})"