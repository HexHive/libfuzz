from typing import List
class Arg:
    name: str
    flag: str
    size: int
    type: str
    # these are attributes from my perspective
    is_type_incomplete: bool
    is_const: bool

    def __init__(self, name, flag, size, type, is_type_incomplete, is_const):
        self.name = name
        self.flag = flag
        self.size = size
        self.type = type
        self.is_type_incomplete = is_type_incomplete
        self.is_const = is_const

    def __str__(self):
        return f"Arg(name={self.name})"

    def __repr__(self):
        return str(self)

    def __key(self):
        arg_lst = []
        arg_lst += [self.name]
        arg_lst += [self.flag]
        arg_lst += [self.size]
        arg_lst += [self.type]
        arg_lst += [self.is_type_incomplete]
        arg_lst += [self.is_const]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other) 

class Api:
    function_name: str
    is_vararg: bool
    return_info: Arg
    arguments_info: List[Arg]

    def __init__(self, function_name: str, is_vararg: bool, 
                    return_info: Arg, arguments_info: List[Arg]):
        self.function_name = function_name
        self.is_vararg = is_vararg
        self.return_info = return_info
        self.arguments_info = arguments_info

    def __str__(self):
        return f"Api(function_name={self.function_name})"

    def __repr__(self):
        return str(self)

    def __key(self):
        arg_lst = []
        arg_lst += [self.function_name]
        arg_lst += [self.is_vararg]
        arg_lst += [hash(self.return_info)]
        arg_lst += [hash(a) for a in self.arguments_info]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other) 