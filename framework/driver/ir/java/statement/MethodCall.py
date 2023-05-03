from typing import List
from driver.ir import Statement
from driver.ir.java.type import JavaType
from driver.ir.java.variable import Variable


class MethodCall(Statement):
    def __init__(self, declaring_class: JavaType, arg_types: List[JavaType]):
        self.declaring_class = declaring_class
        self.arg_types = arg_types

        self.class_var: Variable = None
        self.arg_vars: List[Variable] = [None for _ in arg_types]

    def get_pos_args_types(self):
        return enumerate(self.arg_types)
    
    def set_pos_arg_var(self, pos: int, var: Variable):
        if pos < 0 or pos > len(self.arg_vars):
            raise Exception(f"{pos} out of range [0, {len(self.arg_vars)}]")

        # I must ensure the value is coherent with the argument type
        assert self.arg_types[pos].has_subtype(var.type)

        self.arg_vars[pos] = var

    def set_class_var(self, class_var: Variable):

        assert self.declaring_class.has_subtype(class_var.type)

        for v in self.arg_vars:
            assert class_var != v
        
        self.class_var = class_var

    def __hash__(self):
        arg_lst = []
        arg_lst += [hash(a) for a in self.arg_types]
        arg_lst += [hash(self.declaring_class)]
        return hash(tuple(arg_lst))
