import random, copy
from typing import List, Set, Dict, Tuple, Optional

from grammar import Grammar, Terminal, NonTerminal
from common import Utils, Api, Arg
from . import Driver, Statement, ApiCall, BuffDecl, Type, PointerType, Variable, Context

class DriverGenerator:
    concretization_logic: Dict[Terminal, ApiCall]

    def __init__(self, apis, coerce, hedader_folder, max_nonterminals = 3):
        self.concretization_logic = self.load_concretization_logic(apis, coerce, hedader_folder)
        self.max_nonterminals = 3

    def create_random_driver(self, grammar: Grammar):
        driver_context_free = self.generate_driver_context_free(grammar)
        driver_second = self.generate_driver_context_aware(driver_context_free)
        return driver_second

    def normalize_type(self, a_type, a_size) -> Type:
        if a_type == "i32":
            return Type("uint32_t", a_size)
        elif a_type == "i64":
            return Type("uint64_t", a_size)
        elif a_type == "i8*":
            return PointerType("char*", Type("char", a_size))
        elif a_type == "void":
            return Type("void", a_size)
        elif a_type.startswith("%struct"):
            if a_type.endswith("*"):
                return PointerType(a_type, Type(a_type[:-1], a_size))
            else:
                return Type(a_type, a_size)
            # return a_type.replace("%struct.", "$")

        raise Exception(f"Type '{a_type}' unknown")

    def load_concretization_logic(self, apis, coerce, hedader_folder) -> Dict[Terminal, ApiCall]:

        concretization_logic = {}

        coerce_info = Utils.read_coerce_log(coerce)
        apis_list = Utils.get_api_list(apis, coerce_info)
        
        for api in apis_list:
            function_name = api.function_name
            return_info = api.return_info
            arguments_info = api.arguments_info

            args_str = []
            for e, arg in enumerate(arguments_info):
                the_type = self.normalize_type(arg.type, arg.size)
                args_str += [the_type]

            if return_info.size == 0:
                ret_type = self.normalize_type('void', 0)
            else:
                ret_type = self.normalize_type(return_info.type, return_info.size)
            
            stmt = ApiCall(function_name, args_str, ret_type)
            
            concretization_logic[Terminal(function_name)] = stmt
            
        return concretization_logic

    def nonterminals(self, terms):
        return [s for s in terms if isinstance(s, NonTerminal) ]

    def generate_driver_context_free(self, grammar: Grammar):

        symbols = [grammar.get_start_symbol()]
        expansion_trials = 0

        while len(self.nonterminals(symbols)) > 0: # and len(symbols) < 10:
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

        return symbols

    def generate_driver_context_aware(self, driver_ctx_free) -> Driver:

        new_statement = lambda x: copy.deepcopy(self.concretization_logic[x]) 
        statements = [ new_statement(s) for s in driver_ctx_free if s.name != "end" ]
        
        context = Context()
        for statement in statements:
            if isinstance(statement, ApiCall):
                for arg_pos, arg_type in statement.get_pos_args_types():
                    arg_var = context.randomly_gimme_a_var(arg_type, statement.function_name)
                    statement.set_pos_arg_var(arg_pos, arg_var)
                ret_var = context.randomly_gimme_a_var(statement.ret_type, statement.function_name)
                statement.set_ret_var(ret_var)       
            else:
                raise Exception(f"Don't know {statement}")
        statements_context = context.generate_def_buffer()

        return Driver(statements_context + statements, context)