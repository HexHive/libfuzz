#!/usr/bin/env python3

import argparse, json, graphviz, collections

import sys
sys.path.insert(1, '../libraries')
from libfuzzutils import getApiList, read_coerce_log

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
    apis_list = get_api_list(apis, coerce_info)
        
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