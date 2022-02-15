#!/usr/bin/env python3

import argparse, json, graphviz, collections

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

def intersection_args(args_a, args_b):

    intersection_set = set()

    # {"name": "buff", "flag": "ref", "size": 64, "type": "i8*"}
    for arg_a in args_a:
        for arg_b in args_b:
            type_match = arg_a["type"].replace("*", "") == arg_b["type"].replace("*", "")
            size_match = arg_a["size"] == arg_b["size"]

            if type_match: # or size_match:
                intersection_set.add((arg_a["name"], arg_b["name"]))

    return intersection_set

def get_input_output(api):
    input_a = []
    output_a = [api["return_info"]]
    for arg in api["arguments_info"]:
        if arg["flag"] == "ref":
            output_a += [arg]
        
        input_a += [arg]

    return input_a, output_a

def dependency_on(api_a, api_b):

    api_a_functionname = api_a["function_name"]
    api_b_functionname = api_b["function_name"]
    input_a, output_a = get_input_output(api_a)
    input_b, output_b = get_input_output(api_b)

    print("-"*30)

    print(f"does '{api_a_functionname}' depends on '{api_b_functionname}'?")
    print(f"input {input_a}")
    print(f"output {output_a}")

    print()

    print(f"input {input_b}")
    print(f"output {output_b}")

    intersection_ina_outb = intersection_args(input_a, output_b)

    print(f"intersection_ina_outb")
    print(intersection_ina_outb)
    print()

    return len(intersection_ina_outb) != 0

def plot_graph(graph):
    g = graphviz.Digraph('G', filename='dependency_graph.gv')

    for n, adj in graph.items():
        for a in adj:
            g.edge(n, a)

    # g.save()
    # g.render('hello.gv', view=False)  
    g.render()

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

def normalize_coerce_args(api, coerce_info):
    function_name = api["function_name"]
    print(f"doing: {function_name}")
    arguments_info = api["arguments_info"]
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
        arguments_info = list(new_args_ordered.values())
        # print(arguments_info)
        # exit()

        api["arguments_info"] = arguments_info

    return api

def main():
    parser = argparse.ArgumentParser(description='Generate dependency graph')
    parser.add_argument('--apis', type=str, help='The API log from the compilation')
    parser.add_argument('--coerce', type=str, help='Map between coerce and C args')
    parser.add_argument('--header', type=str, help='The library header file')

    args = parser.parse_args()

    apis = args.apis
    header = args.header
    coerce = args.coerce

    print(f"APIs: {apis}")
    print(f"Header: {header}")
    print(f"Coerce: {coerce}")

    coerce_info = read_coerce_log(coerce)

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
            apis_list += [normalize_coerce_args(api, coerce_info)]
            # print(apis_list)
            # exit()
        
    print()
    print("Found these APIs:")
    for api in apis_list:
        # print(api)
        print(api["function_name"])

    dependency_graph = {}
    for api_a in apis_list:
        for api_b in apis_list:
            api_a_functionname = api_a["function_name"]
            api_b_functionname = api_b["function_name"]
            # if api_a_functionname != api_b_functionname:
            # does api_a depend on api_b ?
            if dependency_on(api_a, api_b):
                api_a_depdences = dependency_graph.get(api_a_functionname, [])
                api_a_depdences += [api_b_functionname]
                dependency_graph[api_a_functionname] = api_a_depdences
        
    # exit()

    print()
    print("Dependency graph")
    for f, ds in dependency_graph.items():
        d_str = ", ".join(ds)
        print(f"{f} depends on: {d_str}")

    plot_graph(dependency_graph)

    with open("dependency_graph.json", "w") as f:
        json.dump(dependency_graph, f, indent=4, sort_keys=True)

if __name__ == "__main__":
    main()