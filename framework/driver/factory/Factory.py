from abc import ABC, abstractmethod

import copy, re

from driver import Driver
from driver.ir import Type, PointerType

class Factory(ABC):

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def create_random_driver(self) -> Driver:
        pass

    @staticmethod
    def normalize_type(a_type, a_size, a_flag, a_is_incomplete, a_is_const) -> Type:
        
        if a_flag == "ref" or a_flag == "ret":
            if not re.search("\*$", a_type) and "*" in a_type:
                raise Exception(f"Type '{a_type}' is not a valid pointer")
        # elif a_flag == "fun" and "(" in a_type :
        #     # FIXME: for the time being, function pointers become i8*
        #     # FIXME: add casting in the backend, if needed (?)
        #     a_type = "char*"
        elif a_flag == "val":
            if "*" in a_type:
                raise Exception(f"Type '{a_type}' seems a pointer while expecting a 'val'")

        pointer_level = a_type.count("*")
        a_type_core = a_type.replace("*", "")

        type_core = Type(a_type_core, a_size, a_is_incomplete, a_is_const)

        return_type = type_core
        for x in range(1, pointer_level + 1):
            return_type = copy.deepcopy(PointerType( a_type_core + "*"*x , copy.deepcopy(return_type)))

        if isinstance(return_type, PointerType):
            return_type.to_function = a_flag == "fun" and "(" in a_type

        return return_type