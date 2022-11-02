from typing import List, Dict, Set #, Tuple, Optional
from enum import Enum

class Access(Enum):
    READ = 1
    WRITE = 2
    RETURN = 3
    NONE = 4

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

class AccessTypeSet:
    access_type_set: Set[AccessType]

    def __init__(self, access_type_set: Set[AccessType]):
        self.access_type_set = access_type_set

    def __len__(self):
        return len(access_type_set)

    def __str__(self):
        return f"ATS(#access_type={len(self.access_type_set)})"

    def __repr__(self):
        return str(self)

    def __iter__(self):
        for at in self.access_type_set:
            yield at

class FunctionConditions:
    function_name: str
    params_at: List[AccessTypeSet]
    return_at: AccessTypeSet

    def __init__(self, function_name: str, params_at: List[AccessTypeSet],
                    return_at: AccessTypeSet):
        self.function_name = function_name
        self.params_at = params_at
        self.return_at = return_at

    def __str__(self):
        return f"FunConds(fun_name={self.function_name})"
    
    def __repr__(self):
        return str(self)

class FunctionConditionsSet:
    fun_cond_set: Dict[str, FunctionConditions]

    def __init__(self):
        self.fun_cond_set = {}

    def add_function_conditions(self, fun_cond: FunctionConditions):
        self.fun_cond_set[fun_cond.function_name] = fun_cond

    def get_function_conditions(self, fun_name: str):
        return fun_cond_set[fun_name]

    def __iter__(self):
        for k, v in self.fun_cond_set.items():
            yield k, v

    def __str__(self):
        return f"FCS(#funcs={len(self.fun_cond_set)})"
    
    def __repr__(self):
        return str(self)