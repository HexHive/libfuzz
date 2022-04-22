
from dependency import DependencyGraph

from . import Grammar, Terminal, NonTerminal, Symbol, ExpantionRule

class GrammarGenerator:
    def __init__(self, start_term):
        self.start_term = start_term
        self.end_term = Terminal("end")

    def create(self, dgraph: DependencyGraph) -> Grammar:

        grammar = Grammar(self.start_term)

        inv_dep_graph = dict((k, set()) for k in list(dgraph.keys()))

        # print(dep_graph)

        for api, deps in dgraph.items():
            for dep in deps:
                if not dep in inv_dep_graph:
                    inv_dep_graph[dep] = set()
                
                inv_dep_graph[dep].add(api)

        for api in inv_dep_graph.keys():
            # nt = NonTerminal(api.function_name + "_nt")
            nt = NonTerminal(api.function_name)
            expantion_rule = ExpantionRule([nt])
            grammar.add_expantion_rule(self.start_term, expantion_rule)

        expantion_rule = ExpantionRule([self.end_term])
        grammar.add_expantion_rule(self.start_term, expantion_rule)


        for api, nexts in inv_dep_graph.items():
            # nt = NonTerminal(api.function_name + "_nt")
            nt = NonTerminal(api.function_name)
            t = Terminal(api.function_name)

            for n in nexts:
                # nnt = NonTerminal(n.function_name + "_nt")
                nnt = NonTerminal(n.function_name)
                expantion_rule = ExpantionRule([t, nnt])
                grammar.add_expantion_rule(nt, expantion_rule)

            expantion_rule = ExpantionRule([t, nt])
            grammar.add_expantion_rule(nt, expantion_rule)

            expantion_rule = ExpantionRule([t, self.start_term])
            grammar.add_expantion_rule(nt, expantion_rule)

            


        #     grammar[f"<{api}>"] = [ f"{api};<{n}>" for n in nexts ] + [f"{api};<start>"]

        return grammar

# import re, random
# import argparse, json, graphviz, collections

# RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')

# import sys
# sys.path.insert(1, '../libraries')
# from libfuzzutils import get_api_list, read_coerce_log

# def get_grammar(dependency_graph):

#     # {"close": ["connect","close"],
#     # "connect": ["connect", "send_msg", "receive_msg", "close"],
#     # "receive_msg": [ "connect", "send_msg", "receive_msg", "close"],
#     # "send_msg": [ "connect", "send_msg", "receive_msg", "close" ] }

#     # {"<start>": ["<open_conn>", "<close_conn>", "<send>", "<recv>", "<end>"],
#     #     "<open_conn>": ["open_conn;<open_conn>", "open_conn;<send>", "open_conn;<close_conn>", "open_conn;<end>"],
#     #     "<send>": ["send;<open_conn>", "send;<send>", "send;<close_conn>", "send;<recv>", "send;<end>"],
#     #     "<recv>": ["recv;<open_conn>", "recv;<send>", "recv;<close_conn>", "recv;<recv>", "recv;<end>"],
#     #     "<close_conn>": ["close_conn;<open_conn>", "close_conn;<send>", "close_conn;<close_conn>", "close_conn;<end>"],
#     #     "<end>": [""] 
#     # }

#     