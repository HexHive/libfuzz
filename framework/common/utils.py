
import json, collections

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
    def get_api_list(apis, coerce_info):

        # TODO: make a white list form the original header
        blacklist = ["__cxx_global_var_init", "_GLOBAL__sub_I_network_lib.cpp"]

        apis_list = []
        with open(apis) as  f:
            for l in f:
                if not l.strip():
                    continue
                if l.startswith("#"):
                    continue
                api = json.loads(l)
                if api["function_name"] in blacklist:
                    continue
                apis_list += [Utils.normalize_coerce_args(api, coerce_info)]
                # print(apis_list)
                # exit()

        return apis_list

    @staticmethod
    def normalize_coerce_args(api, coerce_info) -> Api:
        function_name = api["function_name"]
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
            for a_json in arguments_info_json:
                a = Arg(a_json["name"], a_json["flag"], 
                        a_json["size"], a_json["type"])

                arguments_info.append(a)

        else:
            arguments_info_json = arguments_info
            arguments_info = []
            for a_json in arguments_info_json:
                a = Arg(a_json["name"], a_json["flag"], 
                        a_json["size"], a_json["type"])

                arguments_info.append(a)

        return_info = Arg(return_info["name"], return_info["flag"],
                            return_info["size"], return_info["type"])

        return Api(function_name, return_info, arguments_info)
