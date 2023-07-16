from typing import List
from driver.ir.java.type import ArrayType
from framework.driver.ir.java.type import JavaType
from . import MethodCall

class ArrayCreate(MethodCall):
    def __init__(self, declaring_class: ArrayType, init_len=10):
        super().__init__(declaring_class, declaring_class, [], [])
        self.init_len = init_len
        self.next_fulfill_pos = 0

    def get_all_type(self) -> List[JavaType]:
        return []
    
    def copy(self):
        return ArrayCreate(self.declaring_class, self.init_len)

    def __hash__(self):
        arg_lst = [super().__hash__()]
        arg_lst += [self.__class__.__name__]
        arg_lst += [self.init_len]
        return hash(tuple(arg_lst))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.declaring_class.rawType.className},dimension={self.declaring_class.dimension})"