from typing import List
class Arg:
    name: str
    type: str

    def __init__(self, name: str, type: str):
        self.name = name
        self.type = type

class C_Arg(Arg):
    flag: str
    size: int

    # these are attributes from my perspective
    is_type_incomplete: bool
    is_const: bool

    def __init__(self, name, flag, size, type, is_type_incomplete, is_const):
        super().__init__(name, type)
        self.flag = flag
        self.size = size
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
 
class Java_Arg(Arg):
    package_name: str
    # dimension is used for array. By default it is 0, indicates this type is not an array
    dimension: int

    def __init__(self, name: str, type: str, package_name: str, dimension=0):
        super().__init__(name, type)
        self.package_name = package_name
        self.dimension = dimension

    def __key(self):
        arg_lst = []
        arg_lst += [self.name]
        arg_lst += [self.type]
        arg_lst += [self.package_name]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other) 

class Api:
    function_name: str
    return_info: Arg
    arguments_info: List[Arg]

    def __init__(self, function_name: str, return_info: Arg, arguments_info: List[Arg]):
        self.function_name = function_name
        self.return_info = return_info
        self.arguments_info = arguments_info

class C_Api(Api):
    is_vararg: bool

    def __init__(self, function_name: str, is_vararg: bool, 
                    return_info: C_Arg, arguments_info: List[C_Arg]):
        super().__init__(function_name, return_info, arguments_info)
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

class Java_Api(Api):
    declaring_clazz: str
    exceptions: List[Java_Arg]
    is_static: bool
    is_final: bool
    is_abstract: bool
    access_modifier: str

    def __init__(self, function_name: str, declaring_clazz: Java_Arg, return_info: Java_Arg, arguments_info: List[Java_Arg], exceptions: List[Java_Arg], is_static: bool, is_final: bool, is_abstract: bool, access_modifier: str):
        super().__init__(function_name, return_info, arguments_info)
        self.declaring_clazz = declaring_clazz
        self.exceptions = exceptions
        self.is_abstract = is_abstract
        self.is_final = is_final
        self.is_static = is_static
        self.access_modifier = access_modifier
    
    def __key(self):
        arg_lst = []
        arg_lst += [self.function_name]
        arg_lst += [hash(self.return_info)]
        arg_lst += [hash(self.declaring_clazz)]
        arg_lst += [hash(a) for a in self.arguments_info]
        arg_lst += [hash(a) for a in self.exceptions]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other)