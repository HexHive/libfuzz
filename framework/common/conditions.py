from typing import List, Dict, Set #, Tuple, Optional
from enum import Enum

class Access(Enum):
    READ = 1
    WRITE = 2
    RETURN = 3
    CREATE = 4
    DELETE = 5
    NONE = 6

class AccessType:
    access: Access
    fields: List[int]

    def __init__(self, access: Access, fields: List[int]):
        self.access = access
        self.fields = fields

    def __str__(self):
        ff = ".".join([f"{f}" for f in self.fields])
        return f"AccessType(access={self.access},fields={ff})"

    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key + type
    def __hash__(self):
        h_fld = hash(tuple(self.fields))
        h_acc = hash(self.access)
        return hash((h_fld, h_acc, str(self.__class__.__name__)))

    def __eq__(self, other):
        return hash(self) == hash(other)

class AccessTypeSet:
    access_type_set: Set[AccessType]

    def __init__(self, access_type_set: Set[AccessType] = set()):
        self.access_type_set = access_type_set

    def __len__(self):
        return len(self.access_type_set)

    def __str__(self):
        return f"ATS(#access_type={len(self.access_type_set)})"

    def pprint(self):
        print(str(self.access_type_set))

    def __repr__(self):
        return str(self)

    def __iter__(self):
        for at in self.access_type_set:
            yield at

    # I want this class Immutable!
    def union(self, other: 'AccessTypeSet') -> 'AccessTypeSet':
        tmp = self.access_type_set.union(other.access_type_set)
        return AccessTypeSet(tmp)

    # for an element, the hash is just the key + type
    def __hash__(self):
        h_ats = hash(tuple(self.access_type_set))
        return hash((h_ats, str(self.__class__.__name__)))

    def __eq__(self, other):
        return hash(self) == hash(other)

class FunctionConditions:
    function_name: str
    argument_at: List[AccessTypeSet]
    return_at: AccessTypeSet

    def __init__(self, function_name: str, argument_at: List[AccessTypeSet],
                    return_at: AccessTypeSet):
        self.function_name = function_name
        self.argument_at = argument_at
        self.return_at = return_at

    def __str__(self):
        return f"FunConds(fun_name={self.function_name})"
    
    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key + type
    def __hash__(self):
        h_args = tuple([hash(arg) for arg in self.argument_at])
        h_ret = hash(self.return_at)
        h_funname = hash(self.function_name)
        return hash((h_args, h_ret, h_funname, str(self.__class__.__name__)))

    def __eq__(self, other):
        return hash(self) == hash(other)

class FunctionConditionsSet:
    fun_cond_set: Dict[str, FunctionConditions]

    def __init__(self):
        self.fun_cond_set = {}

    def add_function_conditions(self, fun_cond: FunctionConditions):
        self.fun_cond_set[fun_cond.function_name] = fun_cond

    def get_function_conditions(self, fun_name: str):
        return self.fun_cond_set[fun_name]

    def __iter__(self):
        for k, v in self.fun_cond_set.items():
            yield k, v

    def __str__(self):
        return f"FCS(#funcs={len(self.fun_cond_set)})"
    
    def __repr__(self):
        return str(self)

    # for an element, the hash is just the key + type
    def __hash__(self):
        l_funcondset = [hash(v) for _, v in self.fun_cond_set.items()]
        h_funcondset = tuple(l_funcondset)
        return hash((h_funcondset, str(self.__class__.__name__)))

    def __eq__(self, other):
        return hash(self) == hash(other)