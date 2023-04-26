from typing import List
from driver.ir.java.type import ArrayType
from driver.ir.java.variable import Variable
from . import MethodCall

class ArrayCreate(MethodCall):
    def __init__(self, declaring_class: ArrayType, init_len=10):
        self.declaring_class = declaring_class
        self.arg_types = []
        self.init_len = init_len

        self.class_var = None
        self.arg_vars = []

    def __hash__(self):
        arg_lst = [super().__hash__()]
        arg_lst += [self.__class__.__name__]
        arg_lst += [self.declaring_class.dimension]
        arg_lst += [self.init_len]
        return hash(tuple(arg_lst))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.declaring_class.rawType.className},dimension={self.declaring_class.dimension})"