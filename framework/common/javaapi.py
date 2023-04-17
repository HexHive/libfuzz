from typing import List
class JavaArg:
    def __init__(self, name, rawType: str, argType: List[str]):
        self.name = name
        self.rawType = rawType
        self.argType = argType

    def is_primitive(self):
        return not "." in self.rawType

    def __str__(self):
        return f"JavaArg(name={self.name})"

    def __repr__(self):
        return str(self)

    def __key(self):
        arg_lst = []
        arg_lst += [self.name]
        arg_lst += [self.rawType]
        arg_lst += self.argType
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other) 

class JavaApi:
    def __init__(self, function_name: str, return_info: JavaArg, arguments_info: List[JavaArg], exception_info: List[JavaArg], declaring_class: JavaArg, is_constructor: bool, modifier: int):
        self.function_name = function_name
        self.return_info = return_info
        self.arguments_info = arguments_info
        self.exceptions = exception_info
        self.declaring_class = declaring_class
        self.is_constructor = is_constructor
        self.modifier = modifier

    def is_static(self):
        return self.modifier & 0x8
    
    def is_public(self):
        return self.modifier & 0x1

    def is_private(self):
        return self.modifier & 0x2
    
    def is_protected(self):
        return self.modifier & 0x4
    
    def is_abstract(self):
        return self.modifier & 0x400

    def __str__(self):
        return f"JavaApi(function_name={self.declaring_class.rawType}.{self.function_name})"

    def __repr__(self):
        return str(self)

    def __key(self):
        arg_lst = []
        arg_lst += [self.function_name]
        arg_lst += [hash(self.return_info)]
        arg_lst += [hash(a) for a in self.arguments_info]
        arg_lst += [hash(a) for a in self.exceptions]
        arg_lst += [hash(self.declaring_class)]
        return tuple(arg_lst)

    def __hash__(self):
        return hash(self.__key())

    def __eq__(self, other):
        return hash(self) == hash(other) 