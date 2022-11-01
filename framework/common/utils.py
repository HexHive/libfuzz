
import json, collections, copy
from typing import List, Set, Dict, Tuple, Optional

from .api import Api, Arg

class CoerceArgument:
    def __init__(self, original_type):
        self.original_type = original_type
        self.coerce_names = []
        self.coerce_types = []
        self.coerce_sizes = []
        self.arg_pos = []

    def getSize(self):
        return sum(self.coerce_sizes)

    def getMinPos(self):
        return min(self.arg_pos)

    def getOriginalPos(self):
        return set(self.arg_pos)

    def add_coerce_argument(self, arg_pos, coerce_name, coerce_type, coerce_size):
        self.arg_pos += [arg_pos]
        self.coerce_names += [coerce_name]
        self.coerce_types += [coerce_type]
        self.coerce_sizes += [coerce_size]

    def toString(self):
        return json.dumps(self.__dict__)

    def __str__(self):
        return self.toString()

    def __repr__(self):
        return self.toString()

class CoerceFunction:
    def __init__(self, f_name):
        self.function_name = f_name
        self.arguments = {}

    def add_coerce_argument(self, arg_pos, original_name, original_type, coerce_name, coerce_type, coerce_size):
        # self.arguments[arg_pos] = CoerceArgument(original_name, original_type, coerce_name, coerce_type, coerce_size)

        cArg = self.arguments.get(original_name, None)

        if cArg is None:
            cArg = CoerceArgument(original_type)
            
        cArg.add_coerce_argument(arg_pos, coerce_name, coerce_type, coerce_size)

        self.arguments[original_name] = cArg

    def toString(self):
        s = self.function_name + " " + str(self.arguments)
        # return json.dumps(self.__dict__.items())
        return s

    def __str__(self):
        return self.toString()

    def __repr__(self):
        return self.toString()

class Utils:
    @staticmethod
    def read_coerce_log(coerce_log_file):

        coerce_info = {}

        with open(coerce_log_file, 'r') as f:
            for l in f:
                l = l.strip()
                if not l:
                    continue
                l_arr = l.split("|")

                f_name = l_arr[0]
                arg_pos = int(l_arr[1])
                original_name = l_arr[2]
                original_type = l_arr[3]
                coerce_name = l_arr[4]
                coerce_type = l_arr[5]
                coerce_size = int(l_arr[6])

                cFunc = coerce_info.get(f_name, None)
                if cFunc is None:
                    cFunc = CoerceFunction(f_name)
                cFunc.add_coerce_argument(arg_pos, original_name, original_type, coerce_name, coerce_type, coerce_size)

                coerce_info[f_name] = cFunc

        return coerce_info

    @staticmethod
    def get_incomplete_types_list(incomplete_types):
        incomplete_types_list = []
        with open(incomplete_types) as f:
            for l in f:
                incomplete_types_list += [l.strip()]

        return incomplete_types_list

    @staticmethod
    def get_apis_clang_list(apis_clang):

        apis_clang_list = {}

        with open(apis_clang) as  f:
            for l in f:
                if not l.strip():
                    continue
                if l.startswith("#"):
                    continue
                api = json.loads(l)

                function_name = api["function_name"]

                if function_name in apis_clang_list:
                    raise Exception(f"Function '{function_name}' already extracted!")

                apis_clang_list[function_name] = copy.deepcopy(api)
        
        return apis_clang_list

    @staticmethod
    def get_api_list(apis_llvm, apis_clang, coerce_map, hedader_folder, incomplete_types) -> List[Api]:

        coerce_info = Utils.read_coerce_log(coerce_map)
        included_functions = Utils.get_include_functions(hedader_folder)
        incomplete_types_list = Utils.get_incomplete_types_list(incomplete_types)

        # TODO: make a white list form the original header
        blacklist = ["__cxx_global_var_init", "_GLOBAL__sub_I_network_lib.cpp"]

        apis_clang_list = Utils.get_apis_clang_list(apis_clang)

        apis_list = []
        with open(apis_llvm) as  f:
            for l in f:
                if not l.strip():
                    continue
                if l.startswith("#"):
                    continue
                try:
                    api = json.loads(l)
                except Exception as e: 
                    from IPython import embed; embed(); exit()
                function_name = api["function_name"]
                if function_name in blacklist:
                    continue
                if not function_name in included_functions:
                    continue
                apis_list += [Utils.normalize_coerce_args(api, apis_clang_list, coerce_info, incomplete_types_list)]
                # print(apis_list)
                # exit()

        return apis_list

    @staticmethod
    def normalize_coerce_args(api, apis_clang_list, coerce_info, incomplete_types_list) -> Api:
        function_name = api["function_name"]
        is_vararg = api["is_vararg"]
        # print(f"doing: {function_name}")
        arguments_info = api["arguments_info"]
        return_info = api["return_info"]

        if function_name in coerce_info:
            coerce_arguments = coerce_info[function_name].arguments

            # print("the function has coerce arguments")
            # print(coerce_arguments)
            # print(arguments_info)

            args_to_keep = set(range(len(arguments_info)))
            new_args = {}
            for arg_name, args_coerce in coerce_arguments.items():

                arg = {}
                arg["name"] = arg_name
                arg["flag"] = "val"
                arg["size"] = args_coerce.getSize()
                # normalize type name
                arg["type"] = "%{}".format(args_coerce.original_type.replace(" ", "."))

                arg_pos = args_coerce.getMinPos()
                new_args[arg_pos] = arg

                args_to_keep = args_to_keep - args_coerce.getOriginalPos()

            for pos, arg in enumerate(arguments_info):
                if pos in args_to_keep:
                    new_args[pos] = arg

            # print(new_args)

            new_args_ordered = collections.OrderedDict(sorted(new_args.items()))

            # print(arguments_info)
            arguments_info_json = list(new_args_ordered.values())
            # print(arguments_info)
            # exit()

            arguments_info = []
            for i, a_json in enumerate(arguments_info_json):
                is_incomplete = Utils.is_incomplete(a_json["type"], incomplete_types_list)
                is_const = apis_clang_list[function_name]["arguments_info"][i]["const"]
                a = Arg(a_json["name"], a_json["flag"], 
                        a_json["size"], a_json["type"], is_incomplete, is_const)

                arguments_info.append(a)

        else:
            arguments_info_json = arguments_info
            arguments_info = []
            for i, a_json in enumerate(arguments_info_json):
                is_incomplete = Utils.is_incomplete(a_json["type"], incomplete_types_list)
                is_const = apis_clang_list[function_name]["arguments_info"][i]["const"]
                a = Arg(a_json["name"], a_json["flag"], 
                        a_json["size"], a_json["type"], is_incomplete, is_const)

                arguments_info.append(a)

        is_const = apis_clang_list[function_name]["return_info"]["const"]
        is_incomplete = Utils.is_incomplete(return_info["type"], incomplete_types_list)
        return_info = Arg(return_info["name"], return_info["flag"],
                            return_info["size"], return_info["type"], is_incomplete, is_const)

        # normalize arguments_info and return_info
        if return_info.flag in ["val", "ref"]:
            return_info.type = apis_clang_list[function_name]["return_info"]["type_clang"]
        
        for i, arg_info in enumerate(arguments_info):
            if arg_info.flag in ["val", "ref"]:
                arg_info.type =  apis_clang_list[function_name]["arguments_info"][i]["type_clang"]

        return Api(function_name, is_vararg, return_info, arguments_info)

    @staticmethod
    def is_incomplete(a_type, incomplete_types_list):

        # removing trailing stars
        x = a_type
        while x[-1] == "*":
            x = x[:-1]

        return x in incomplete_types_list

    @staticmethod
    def get_include_functions(hedader_folder) -> List[str]:

        exported_functions = set()

        with open(hedader_folder) as f:
            for l in f:
                l_strip = l.strip()
                p_par = l_strip.find("(")
                exported_functions |= { l_strip[:p_par] }

        return list(exported_functions)