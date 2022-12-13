from typing import List, Set, Dict, Tuple, Optional

import random, copy

from driver import Context
from driver.ir import Variable, Type, Value, PointerType, Address, NullConstant
from . import Conditions
from common.conditions import *

class RunningContext(Context):
    variables_alive:    List[Variable]
    var_to_cond:        Dict[Variable, Conditions]

    def __init__(self):
        super().__init__()
        self.variables_alive = []
        self.var_to_cond = {}

    def has_var_type(self, type: Type) -> bool:

        # FLAVIO: I think this should be like that!
        # TODO: Extract "base" type with a dedicatd method?
        tt = None
        if isinstance(type, PointerType):
            if type.get_pointee_type().is_incomplete:
                tt = type
            else:
                tt = type.get_pointee_type()
        else:
            tt = type
            
        if tt is None:
            raise Exception("can't find a type for 'tt'")

        for v in self.variables_alive:
            if v.get_type() == tt:
                return True

        return False

    def get_value_that_satisfy(self, type: Type,
            cond: AccessTypeSet) -> Optional[Value]:

        # print("Debug get_value_that_satisfy")
        # from IPython import embed; embed(); exit()

        tt = None
        if isinstance(type, PointerType):
            if type.get_pointee_type().is_incomplete:
                tt = type
            else:
                tt = type.get_pointee_type()
        else:
            tt = type
            
        if tt is None:
            raise Exception("can't find a type for 'tt'")

        vars = set()

        # print("Debug get_value_that_satisfy (2)")
        # from IPython import embed; embed(); exit()

        for v in self.variables_alive:
            if v.get_type() == tt:
                if self.var_to_cond[v].are_compatible_with(cond):
                    vars.add(v)

        if len(vars) == 0:
            return None
        else:
            var = random.choice(list(vars))
            if isinstance(type, PointerType):
                return var.get_address()
            return var
    
    def add_variable(self, val: Value, cond: AccessTypeSet):

        if not isinstance(val, Variable):
            raise Exception(f"{val} is not a Variable! :(")

        seek_val = None
        for v in self.variables_alive:
            if v == val:
                seek_val = v
                break

        if seek_val is None:
            self.variables_alive += [val]
            self.var_to_cond[val] = Conditions(cond)
        else:
            self.var_to_cond[val].add_conditions(cond)

    def try_to_get_var(self, type: Type, cond: AccessTypeSet,
                        is_ret: bool = False) -> Value:

        # if I need a void for return, don't bother too much
        if type == self.stub_void and is_ret:
            return NullConstant(self.stub_void)

        if self.has_var_type(type):
            val = self.get_value_that_satisfy(type, cond)
            if val is None:
                if (Conditions.is_unconstraint(cond) and 
                    not type.is_incomplete):
                    val = self.randomly_gimme_a_var(type, "", is_ret)
                else:
                    raise ConditionUnsat()
        else:
            tt = type.get_pointee_type() if isinstance(type, PointerType) else type
            if tt.is_incomplete and not is_ret:
                raise ConditionUnsat()
            else:
                val = self.randomly_gimme_a_var(type, "", is_ret)

        return val

    def update(self, val: Optional[Value], cond: AccessTypeSet):
        if isinstance(val, Variable):
            # I am not sure it should be done here!
            x = AccessType(Access.WRITE, [])
            x2 = AccessTypeSet(set([x]))
            cond2 = cond.union(x2)
            self.add_variable(val, cond2)
        elif isinstance(val, Address):
            x = AccessType(Access.WRITE, [-1])
            x2 = AccessTypeSet(set([x]))
            cond2 = cond.union(x2)
            var = val.get_variable()
            self.add_variable(var, cond2)
        elif isinstance(val, NullConstant):
            # NullConstant does not have conditions
            pass
        else:
            raise Exception(f"I don't know this val: {val}")

    def __copy__(self):
        raise Exception("__copy__ not implemented")
        
class ConditionUnsat(Exception):
    """ConditionUnsat, can't find a suitable variable in the RunningContext"""
    pass