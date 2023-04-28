
import json, collections, copy, os
from typing import List, Set, Dict, Tuple, Optional

from common import Utils

# Extract type system from library (only for structs):
#   - match llvm and clanv api file
#   - first, check if known from table
#   - second, check if in LLVM api
#   - third, check if in list of incomplete types
#   - fourth, get type from LLVM definition through LLVM name (add extraction from condition_extraction)
class DataLayout:
    # so far, only clang_str -> (size in bit)
    layout:     Dict[str, int]
    structs:    Set[str]

    @staticmethod
    def populate(apis_clang_p: str, apis_llvm_p: str,
        incomplete_types_p: str, data_layout_p: str):
        print("DataLayout populate!")

        DataLayout.layout = {}

        apis_clang = Utils.get_apis_clang_list(apis_clang_p)
        apis_llvm = Utils.get_apis_llvm_list(apis_llvm_p)
        incomplete_types = Utils.get_incomplete_types_list(incomplete_types_p)
        data_layout = Utils.get_data_layout(data_layout_p)

        DataLayout.apis_clang = apis_clang
        DataLayout.apis_llvm = apis_llvm
        DataLayout.incomplete_types = incomplete_types
        DataLayout.data_layout = data_layout
        DataLayout.clang_to_llvm_struct = {}

        # loop all the types in apis_clang (args + ret) and try to infer all the
        # types
        for function_name, api in apis_clang.items():
            for arg_pos, arg in enumerate(api["arguments_info"]):
                type_clang = arg["type_clang"]
                DataLayout.populate_table(type_clang, function_name, arg_pos)

            type_clang = api["return_info"]["type_clang"]
            DataLayout.populate_table(type_clang, function_name, -1)

        # print(DataLayout.layout)
        # from IPython import embed; embed(); exit(1)

    @staticmethod
    def get_llvm_type(function_name, arg_pos):
        if arg_pos == -1:
            arg = DataLayout.apis_llvm[function_name]["return_info"]
        else:
            arg = DataLayout.apis_llvm[function_name]["arguments_info"][arg_pos]

        l_type = arg["type"]
        l_size = arg["size"]

        return l_type, l_size

    
    @staticmethod
    def multi_level_size_infer(ttype, function_name, pos, is_original):
        t_size = 0

        # first step, search in the tables
        known_type = False
        try:
            t_size = DataLayout.infer_type_size(ttype)
            known_type = True
        except:
            pass

        # if ttype == "TIFFCodec":
        #     print(f"{ttype}")
        #     from IPython import embed; embed(); exit(1)
        
        if not known_type:
            if function_name not in DataLayout.apis_llvm:
                return 0

            (type_llvm, size_llvm) = DataLayout.get_llvm_type(function_name, pos)

            if is_original:
                t_size = size_llvm
            else:
                type_llvm = type_llvm.replace("*", "")
                if type_llvm in DataLayout.incomplete_types:
                    t_size = 0
                elif type_llvm in DataLayout.data_layout:
                    t_size, _ = DataLayout.data_layout[type_llvm]
                    
                DataLayout.clang_to_llvm_struct[ttype] = type_llvm

        return t_size
    
    @staticmethod
    def populate_table(type_clang, function_name, arg_pos):
        # remove pointers
        tmp_type = type_clang
        pointer_level = tmp_type.count("*")
        is_original = True
        while pointer_level > 0:

            t_size = DataLayout.multi_level_size_infer(tmp_type, function_name, arg_pos, is_original)
            DataLayout.layout[tmp_type] = t_size

            tmp_type = tmp_type[:-1]
            pointer_level = tmp_type.count("*")
            is_original = False

        t_size = t_size = DataLayout.multi_level_size_infer(tmp_type, function_name, arg_pos, is_original)
        DataLayout.layout[tmp_type] = t_size

    @staticmethod
    def infer_type_size(type) -> int:
        # given a clang-like type, try to infer its size
        # NOTE: table written for x86 64

        # any pointer is 8 byes in x86 64
        if "*" in type:
            return 8*8
        elif type == "float":
            return 4*8
        elif type == "double":
            return 8*8
        elif type == "int":
            return 4*8
        elif type == "unsigned int":
            return 4*8
        elif type == "long":
            return 8*8
        elif type == "unsigned long":
            return 8*8
        elif type == "char":
            return 1*8
        elif type == "void":
            return 0
        elif type == "size_t":
            return 8*8
        elif type == "uint8_t":
            return 8
        elif type == "uint32_t":
            return 4*8
        elif type == "uint64_t":
            return 8*8
        elif "(" in type:
            return 0
        elif type == "uint16_t":
            return 8*2
        elif type == "unsigned char":
            return 8
        elif type == "wchar_t":
            return 8*4
        else:
            raise Exception(f"I don't know the size of '{type}'")

    @staticmethod
    def get_type_size(a_type: str) -> int:
        try:
            return DataLayout.infer_type_size(a_type)
        except:
            return DataLayout.layout[a_type]

    @staticmethod
    def is_a_struct(a_type: str) -> bool:
        # for k, s in DataLayout.data_layout.items():
            # if 
        # if "TIFF" in a_type:
        #     print("is_a_struct")
        #     from IPython import embed; embed(); exit(1)
        return a_type in DataLayout.clang_to_llvm_struct
    
    @staticmethod
    def is_primitive_type(a_type: str) -> bool:
        try:
            DataLayout.infer_type_size(a_type)
            return True
        except:
            return False

    @staticmethod
    def has_incomplete_type() -> bool:
        return len(DataLayout.incomplete_types) != 0
    
    @staticmethod
    def has_user_define_init(a_type: str) -> bool:
        # NOTE: in somehow, I should define what types I can handle manually
        
        # if a_type == "UriParserStateA":
        #     return True
        
        # # if a_type == "UriUriA":
        # #     return True
        
        return False