#!/usr/bin/env python3

import re, random
import argparse, json, graphviz, collections

RE_NONTERMINAL = re.compile(r'(<[^<> ]*>)')

import sys
sys.path.insert(1, '../libraries')
from libfuzzutils import get_api_list, read_coerce_log

def load_grammar(grammar_file):

    with open(grammar_file, 'r') as f:
        grammar = json.load(f)

    return grammar

def nonterminals(expansion):
    if isinstance(expansion, tuple):
        expansion = expansion[0]

    return RE_NONTERMINAL.findall(expansion)

def simple_grammar_fuzzer(grammar, start_symbol, max_nonterminals, max_expansion_trials = 100,  log = False):
    """Produce a string from `grammar`.
       `start_symbol`: use a start symbol other than `<start>` (default).
       `max_nonterminals`: the maximum number of nonterminals 
         still left for expansion
       `max_expansion_trials`: maximum # of attempts to produce a string
       `log`: print expansion progress if True"""

    term = start_symbol
    expansion_trials = 0

    while len(nonterminals(term)) > 0:
        symbol_to_expand = random.choice(nonterminals(term))
        expansions = grammar[symbol_to_expand]
        expansion = random.choice(expansions)
        # In later chapters, we allow expansions to be tuples,
        # with the expansion being the first element
        if isinstance(expansion, tuple):
            expansion = expansion[0]

        new_term = term.replace(symbol_to_expand, expansion, 1)

        if len(nonterminals(new_term)) < max_nonterminals:
            term = new_term
            if log:
                print("%-40s" % (symbol_to_expand + " -> " + expansion), term)
            expansion_trials = 0
        else:
            expansion_trials += 1
            if expansion_trials >= max_expansion_trials:
                raise Exception("Cannot expand " + repr(term))

    return term

# statements_semantic = {}

# class SemanticObject:
#     def __init__(self):
#         pass

def create_new_var(t, context, context_counter):
    var_counter = context_counter.get(t, 0)
    new_var = f"{t}_{var_counter}".replace("$", "")
    context[new_var] = t
    context_counter[t] = var_counter + 1

    return new_var

def get_random_var(thet, context):
    a_var = random.choice([v for v, t in context.items() if t == thet])  

    return a_var

def has_vars_type(a_t, context):
    for v, t in context.items():
        if t == a_t:
            return True

    return False

def generate_init_vars(context):

    statements = []

    for v, t in context.items():
        statements += [f"{t[1:]} {v} = input();"]
        # statements += [f"{t[1:]} {v[1:]} = input();"]

    return statements

def get_address_of(variable):
    return f"&{variable}"

def expand_rules(sequence, expansion_rules):

    statements = []

    for token in sequence.split(";"):
        # if token == "open_conn":
        #     statements += ["open_conn($*char, $int, $*conn);"]
        # elif token == "send":
        #     statements += ["$int = send($*char, $int, $conn);"]
        # elif token == "recv":
        #     statements += ["int = send($*char, $int, $conn);"]
        # elif token == "close_conn":
        #     statements += ["close_conn($*conn);"]

        if token in expansion_rules:
            statements += [expansion_rules[token]]

        # if token == "connect":
        #     statements += ["connect($*char, $int, $*conn);"]
        # elif token == "send_msg":
        #     statements += ["$int = send_msg($*char, $int, $conn);"]
        # elif token == "receive_msg":
        #     statements += ["$int = receive_msg($*char, $int, $conn);"]
        # elif token == "close":
        #     statements += ["close($*conn);"]

    GET_VARIABLES = re.compile(r'(\$[a-z0-9_*]*)')

    statements_expanded = []

    context = {}
    context_counter = {}
    for statement in statements:
        variables = GET_VARIABLES.findall(statement)

        for t in variables:
            if t.startswith("$") and t.endswith("*"):

                tt = t.replace("*", "")
                
                # I can decide to add a new var to the context, if I want
                if random.getrandbits(1) == 1 or not has_vars_type(tt, context):
                    # print(f"=> I create a new {tt} to get the address")
                    v = create_new_var(tt, context, context_counter)
                # I pick a var from the context
                else:
                    # print(f"=> I get a random {tt} to get the address")
                    v = get_random_var(tt, context)

                v = get_address_of(v)
                statement = statement.replace(t, v)
                    
            else:
                # if v not in context -> just create
                if not has_vars_type(t, context):
                    # print(f"=> {t} not in context, new one")
                    v = create_new_var(t, context, context_counter)
                    statement = statement.replace(t, v)
                else:
                    # I might get an existing one
                    if random.getrandbits(1) == 1:
                        # print(f"=> wanna pick a random {t} from context")
                        v = get_random_var(t, context)
                        statement = statement.replace(t, v)
                    # or create a new var
                    else:
                        # print(f"=> decided to create a new {t}")
                        v = create_new_var(t, context, context_counter)
                        statement = statement.replace(t, v)
        

        statements_expanded += [statement]

    statements_context = generate_init_vars(context)

    return "\n".join(statements_context + [""] + statements_expanded)

def normalize_type(a_type):
    if a_type == "i32":
        return "$uint32_t"
    elif a_type == "i64":
        return "$uint64_t"
    elif a_type == "i8*":
        return "$char*"
    # elif a_type.startswith("\%\struct"):
    elif a_type.startswith("%struct"):
        return a_type.replace("%struct.", "$")

    print(f"what is? {a_type}")
    exit(1)

def load_expansion_rules(apis, coerce):

    expansion_rules = {}

    coerce_info = read_coerce_log(coerce)
    apis_list = get_api_list(apis, coerce_info)
        
    for api in apis_list:
        function_name = api["function_name"]
        return_info = api["return_info"]
        arguments_info = api["arguments_info"]

        args_str = ""
        for e, arg in enumerate(arguments_info):
            the_type = normalize_type(arg["type"])
            the_name = arg["name"]
            # args_str += f"{the_type} {the_name}"
            args_str += f"{the_type}"
            if e != len(arguments_info) -1:
                args_str += ", "

        if return_info["size"] == 0:
            rule = f"{function_name}({args_str})"
        else:
            ret_type = normalize_type(return_info["type"])
            rule = f"{ret_type} {function_name}({args_str})"
        
        expansion_rules[function_name] = rule
    
    print()
    print(expansion_rules)
    print()
    # exit(1)

    return expansion_rules

def main():

    parser = argparse.ArgumentParser(description='Generate drivers from grammar')
    parser.add_argument('--grammar', type=str, help='The grammar')
    parser.add_argument('--apis', type=str, help='The API log from the compilation')
    parser.add_argument('--coerce', type=str, help='Map between coerce and C args')
    parser.add_argument('--header', type=str, help='The library header file')

    args = parser.parse_args()

    grammar = args.grammar
    apis = args.apis
    header = args.header
    coerce = args.coerce

    print(f"Grammar: {grammar}")
    print(f"APIs: {apis}")
    print(f"Header: {header}")
    print(f"Coerce: {coerce}")

    expansion_rules = load_expansion_rules(apis, coerce)
    grammar = load_grammar(grammar)

    # for i in range(10):
    driver_first = simple_grammar_fuzzer(grammar=grammar, start_symbol="<start>", max_nonterminals=3, log=False)
    print(driver_first)
    print()
    driver_second = expand_rules(driver_first, expansion_rules)
    print(driver_second)

if __name__ == "__main__":
    main()