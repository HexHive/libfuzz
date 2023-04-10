from abc import ABC, abstractmethod

import copy, re

from common import Api, Utils, DataLayout

from driver import Driver
from driver.ir import Type, PointerType, ApiCall, TypeTag

class Factory(ABC):

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def create_random_driver(self) -> Driver:
        pass

    @staticmethod
    def api_to_apicall(api: Api) -> ApiCall:
        function_name = api.function_name
        return_info = api.return_info
        arguments_info = api.arguments_info

        arg_list_type = []
        for _, arg in enumerate(arguments_info):
            # NOTE: for simplicity, const type as arguments can be consider non-const, see `Driver_IR.md` for more info
            the_type = Factory.normalize_type(arg.type, arg.size, arg.flag, arg.is_type_incomplete, False)
            arg_list_type += [the_type]

        if return_info.size == 0:
            ret_type = Factory.normalize_type('void', 0, "val", True, False)
        else:
            ret_type = Factory.normalize_type(return_info.type, return_info.size, return_info.flag, return_info.is_type_incomplete, return_info.is_const)
        
        return ApiCall(api, function_name, arg_list_type, ret_type)

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

        if a_type_core == "void":
            a_is_incomplete = True

        # NOTE: a_size comes wrong from LLVM analysis, I use this trick to fix
        # the size
        a_size = DataLayout.get_type_size(a_type_core)

        type_tag = TypeTag.PRIMITIVE
        if DataLayout.is_a_struct(a_type_core):
            # print("is this a struct?")
            # from IPython import embed; embed(); exit(1)
            type_tag = TypeTag.STRUCT
            
        type_core = Type(a_type_core, a_size, a_is_incomplete, a_is_const, type_tag)

        return_type = type_core
        for x in range(1, pointer_level + 1):
            return_type = copy.deepcopy(PointerType( a_type_core + "*"*x , copy.deepcopy(return_type)))

        if isinstance(return_type, PointerType):
            return_type.to_function = a_flag == "fun" and "(" in a_type

        return return_type