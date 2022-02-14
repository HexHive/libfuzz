#!/usr/bin/env python3

import argparse, json, graphviz

def intersection_args(args_a, args_b):

    intersection_set = set()

    # {"name": "buff", "flag": "ref", "size": 64, "type": "i8*"}
    for arg_a in args_a:
        for arg_b in args_b:
            type_match = arg_a["type"] == arg_b["type"]
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

    input_a, output_a = get_input_output(api_a)
    input_b, output_b = get_input_output(api_b)

    api_a_functionname = api_a["function_name"]
    print(f"for {api_a_functionname}")
    print(f"input {input_a}")
    print(f"output {output_a}")

    api_b_functionname = api_b["function_name"]
    print(f"for {api_b_functionname}")
    print(f"input {input_b}")
    print(f"output {output_b}")

    intersection_ina_outb = intersection_args(input_a, output_b)

    print(f"intersection_ina_outb")
    print(intersection_ina_outb)
    print()

    return len(intersection_ina_outb) != 0

def plot_graph(graph):
    g = graphviz.Digraph('G', filename='hello.gv')

    for n, adj in graph.items():
        for a in adj:
            g.edge(n, a)

    g.view()

def main():
    parser = argparse.ArgumentParser(description='Generate dependency graph')
    parser.add_argument('--apis', type=str, help='The API log from the compilation')
    parser.add_argument('--header', type=str, help='The library header file')

    args = parser.parse_args()

    apis = args.apis
    header = args.header

    print(f"APIs: {apis}")
    print(f"Header: {header}")

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
            apis_list += [api]
        
    print()
    print("Found these APIs:")
    for api in apis_list:
        print(api["function_name"])

    dependency_graph = {}
    for api_a in apis_list:
        for api_b in apis_list:
            api_a_functionname = api_a["function_name"]
            api_b_functionname = api_b["function_name"]
            if api_a_functionname != api_b_functionname:
                # does api_a depend on api_b ?
                if dependency_on(api_a, api_b):
                    api_a_depdences = dependency_graph.get(api_a_functionname, [])
                    api_a_depdences += [api_b_functionname]
                    dependency_graph[api_a_functionname] = api_a_depdences

    print()
    print("Dependency graph")
    for f, ds in dependency_graph.items():
        d_str = ", ".join(ds)
        print(f"{f} depends on: {d_str}")

    # plot_graph(dependency_graph)

if __name__ == "__main__":
    main()