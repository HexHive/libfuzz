from typing import List, Set, Dict, Tuple, Optional

from . import Statement, Type, Variable

class ApiCall(Statement):
    function_name:  str
    arg_types:      List[Type]
    arg_vars:       List[Variable]
    ret_type:       Type
    ret_var:        Variable

    def __init__(self, function_name, arg_types, ret_type):
        super().__init__()
        self.function_name = function_name
        self.arg_types  = arg_types
        self.ret_type   = ret_type

        # these are the objects of the instance of the ApiCall
        self.arg_vars   = [None for x in arg_types]
        self.ret_var    = None

    def get_pos_args_types(self):
        return enumerate(self.arg_types)

    def set_pos_arg_var(self, pos: int, var: Variable):
        if pos < 0 or pos > len(self.arg_vars):
            raise Exception(f"{pos} out of range [0, {len(self.arg_vars)}]")

        self.arg_vars[pos] = var

    def set_ret_var(self, ret_var):
        self.ret_var = ret_var

    # for an element, the hash is just the key + type
    def __hash__(self):
        return hash(self.function_name + str(self.__class__.__name__))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.function_name})"