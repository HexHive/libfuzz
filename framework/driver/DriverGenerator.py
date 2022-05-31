import random, copy, re
from typing import List, Set, Dict, Tuple, Optional

from grammar import Grammar, Terminal, NonTerminal
from common import Utils, Api, Arg
from . import Driver, Statement, ApiCall, BuffDecl, Type, PointerType, Variable, Context

class DriverGenerator:
    concretization_logic: Dict[Terminal, ApiCall]

    def __init__(self, apis, coerce, hedader_folder, driver_size, max_nonterminals = 3):
        self.concretization_logic = self.load_concretization_logic(apis, coerce, hedader_folder)
        self.max_nonterminals = 3
        self.driver_size = driver_size

    def create_random_driver(self, grammar: Grammar):
        driver_context_free = self.generate_driver_context_free(grammar)
        driver_second = self.generate_driver_context_aware(driver_context_free)
        return driver_second

    def normalize_type(self, a_type, a_size, a_flag) -> Type:
        
        if a_flag == "ref" or a_flag == "ret":
            if not re.search("\*$", a_type) and "*" in a_type:
                raise Exception(f"Type '{a_type}' is not a valid pointer")
        elif a_flag == "fun":
            # FIXME: for the time being, function pointers become i8*
            a_type = "i8*"
        elif a_flag == "val":
            if "*" in a_type:
                raise Exception(f"Type '{a_type}' seems a pointer while expecting a 'val'")

        pointer_level = a_type.count("*")
        a_type_core = a_type.replace("*", "")

        if a_type_core == "i8":
            type_core = Type("char", a_size)
        elif a_type_core == "i16":
            type_core = Type("uint16_t", a_size)
        elif a_type_core == "i32":
            type_core = Type("uint32_t", a_size)
        elif a_type_core == "i64":
            type_core = Type("uint64_t", a_size)
        elif a_type_core == "void":
            type_core = Type("void", a_size)
        elif a_type_core == "float":
            type_core = Type("float", a_size)
        elif a_type_core == "double":
            type_core = Type("double", a_size)
        elif a_type_core.startswith("%struct"):
            # FIXME: this is very wrong! a_size should be according to the type, if it is a pointer, size will be 64 (or 32).
            # TODO: buid a map that matches custom structures and real size, to extract from LLVM
            type_core = Type(a_type_core[1:], a_size)
        else:
            raise Exception(f"Type '{a_type_core}' unknown")

        return_type = type_core
        for x in range(1, pointer_level + 1):
            return_type = copy.deepcopy(PointerType( a_type_core + "*"*x , copy.deepcopy(return_type)))

        return return_type

    def load_concretization_logic(self, apis, coerce, hedader_folder) -> Dict[Terminal, ApiCall]:

        concretization_logic = {}

        apis_list = Utils.get_api_list(apis, coerce, hedader_folder)
        
        for api in apis_list:
            function_name = api.function_name
            return_info = api.return_info
            arguments_info = api.arguments_info

            args_str = []
            for e, arg in enumerate(arguments_info):
                the_type = self.normalize_type(arg.type, arg.size, arg.flag)
                args_str += [the_type]

            if return_info.size == 0:
                ret_type = self.normalize_type('void', 0, "val")
            else:
                ret_type = self.normalize_type(return_info.type, return_info.size, return_info.flag)
            
            stmt = ApiCall(function_name, args_str, ret_type)
            
            concretization_logic[Terminal(function_name)] = stmt
            
        return concretization_logic

    def nonterminals(self, terms):
        return [s for s in terms if isinstance(s, NonTerminal) ]

    def generate_driver_context_free(self, grammar: Grammar):

        symbols = [grammar.get_start_symbol()]
        expansion_trials = 0

        while len(self.nonterminals(symbols)) > 0 and len(symbols) <= self.driver_size:
            symbol_to_expand = random.choice(self.nonterminals(symbols))

            expansions = grammar[symbol_to_expand]
            expansion = random.choice(tuple(expansions))

            old_symbol_idx = symbols.index(symbol_to_expand)
            del symbols[old_symbol_idx]
            for i, e in enumerate(expansion):
                symbols.insert(old_symbol_idx + i, e)

            if len(self.nonterminals(symbols)) < self.max_nonterminals:
                expansion_trials = 0
            else:
                expansion_trials += 1
                if expansion_trials >= self.max_expansion_trials:
                    raise Exception(f"Cannot expand {symbol_to_expand}")

        symbols_only_terminal = []
        for s in symbols:
            if isinstance(s, Terminal):
                symbols_only_terminal += [copy.deepcopy(s)]
            elif isinstance(s, NonTerminal):
                symbols_only_terminal += [copy.deepcopy(s).convertToTerminal()]
            else:
                raise Exception(f"what is '{s}'?")

        return symbols_only_terminal

    def generate_driver_context_aware(self, driver_ctx_free) -> Driver:

        new_statement = lambda x: copy.deepcopy(self.concretization_logic[x]) 
        statements = [ new_statement(s) for s in driver_ctx_free if s.name != "end" ]

        print("after statements created!")
        # from IPython import embed; embed(); exit()
        
        context = Context()
        for statement in statements:
            if isinstance(statement, ApiCall):
                for arg_pos, arg_type in statement.get_pos_args_types():
                    arg_var = context.randomly_gimme_a_var(arg_type, statement.function_name)
                    statement.set_pos_arg_var(arg_pos, arg_var)
                ret_var = context.randomly_gimme_a_var(statement.ret_type, statement.function_name, True)
                statement.set_ret_var(ret_var)       
            else:
                raise Exception(f"Don't know {statement}")
        statements_context = context.generate_def_buffer()

        return Driver(statements_context + statements, context)