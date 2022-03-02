from typing import List, Set, Dict, Tuple, Optional
import random

from . import Type, PointerType, Variable, VarDecl, Statement

class Context:
    # trace the variable alives in this context
    vars_alive = Set[Variable]
    # trace indexes to create new unique vars
    vars_counter = Dict[Type, int]

    def __init__(self):
        self.vars_alive = set()
        self.vars_counter = {}
        self.stub_void = Type("void")

    def create_new_var(self, type: Type):

        # if I require a void var, I just return without put in the context
        if type == self.stub_void:
            return Variable("void_stub", self.stub_void)

        var_counter = self.vars_counter.get(type, 0)

        var_name = f"{type.token}_{var_counter}"

        new_var = Variable(var_name, type)

        self.vars_alive.add(new_var)
        self.vars_counter[type] = var_counter + 1

        return new_var

    def has_vars_type(self, type: Type):
        for v in self.vars_alive:
            if v.get_type() == type:
                return True

        return False
    
    def get_random_var(self, type: Type):
        a_var = random.choice([v for v in self.vars_alive if v.get_type() == type])  
        return a_var

    def randomly_gimme_a_var(self, type: Type):

        v = None

        if isinstance(type, PointerType):
            tt = type.get_pointee_type()
            
            # I can decide to add a new var to the context, if I want
            if random.getrandbits(1) == 1 or not self.has_vars_type(tt):
                # print(f"=> I create a new {tt} to get the address")
                v = self.create_new_var(tt)
            # I pick a var from the context
            else:
                # print(f"=> I get a random {tt} to get the address")
                v = self.get_random_var(tt)

            # v = get_address_of(v)
            v = v.get_address()
                        
        else:
            # if v not in context -> just create
            if not self.has_vars_type(type):
                # print(f"=> {t} not in context, new one")
                v = self.create_new_var(type)
            else:
                # I might get an existing one
                if random.getrandbits(1) == 1:
                    # print(f"=> wanna pick a random {t} from context")
                    v = self.get_random_var(type)
                # or create a new var
                else:
                    # print(f"=> decided to create a new {t}")
                    v = self.create_new_var(type)

        if v is None:
            raise Exception("v was not assigned!")

        return v
    
    def generate_def_vars(self) -> List[Statement]:
        statements = []
        for v in self.vars_alive:
            # tkn = f"{t.token}-{v.token}"
            statements += [VarDecl(v)]
        return statements
        