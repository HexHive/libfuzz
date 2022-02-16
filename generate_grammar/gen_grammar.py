#!/usr/bin/env python3

import re, random
import argparse, json, graphviz, collections

RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')

import sys
sys.path.insert(1, '../libraries')
from libfuzzutils import get_api_list, read_coerce_log

def get_grammar(dependency_graph):

    # {"close": ["connect","close"],
    # "connect": ["connect", "send_msg", "receive_msg", "close"],
    # "receive_msg": [ "connect", "send_msg", "receive_msg", "close"],
    # "send_msg": [ "connect", "send_msg", "receive_msg", "close" ] }

    # {"<start>": ["<open_conn>", "<close_conn>", "<send>", "<recv>", "<end>"],
    #     "<open_conn>": ["open_conn;<open_conn>", "open_conn;<send>", "open_conn;<close_conn>", "open_conn;<end>"],
    #     "<send>": ["send;<open_conn>", "send;<send>", "send;<close_conn>", "send;<recv>", "send;<end>"],
    #     "<recv>": ["recv;<open_conn>", "recv;<send>", "recv;<close_conn>", "recv;<recv>", "recv;<end>"],
    #     "<close_conn>": ["close_conn;<open_conn>", "close_conn;<send>", "close_conn;<close_conn>", "close_conn;<end>"],
    #     "<end>": [""] 
    # }

    dep_graph = None
    with open(dependency_graph, 'r') as f:
        dep_graph = json.load(f)

    inv_dep_graph = dict((k, set()) for k in list(dep_graph.keys()))

    # print(dep_graph)

    dep_graph.items()

    for api, deps in dep_graph.items():
        for dep in deps:
            inv_dep_graph[dep].add(api)

    # print(inv_dep_graph)

    grammar = {}

    grammar["<start>"] = list([ f"<{api}>" for api in inv_dep_graph.keys() ]) + ["<end>"]
    for api, nexts in inv_dep_graph.items():
        grammar[f"<{api}>"] = [ f"{api};<{n}>" for n in nexts ] + [f"{api};<start>"]

    grammar["<end>"] = [""]

    print(grammar)

    return grammar

def main():

    parser = argparse.ArgumentParser(description='Generate drivers from dependency graph')
    parser.add_argument('--dependency_graph', type=str, help='The dependency graph')
    parser.add_argument('--apis', type=str, help='The API log from the compilation')
    parser.add_argument('--coerce', type=str, help='Map between coerce and C args')
    parser.add_argument('--header', type=str, help='The library header file')

    args = parser.parse_args()

    dependency_graph = args.dependency_graph
    apis = args.apis
    header = args.header
    coerce = args.coerce

    print(f"Dependency Graph: {dependency_graph}")
    print(f"APIs: {apis}")
    print(f"Header: {header}")
    print(f"Coerce: {coerce}")

    grammar = get_grammar(dependency_graph)

    with open("grammar.json", "w") as f:
        json.dump(grammar, f)

if __name__ == "__main__":
    main()