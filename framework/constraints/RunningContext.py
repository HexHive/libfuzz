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
        # TODO: Extract "base" type with a dedicated method?
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

    def get_value_that_strictly_satisfy(self, type: Type,
            cond: AccessTypeSet) -> Optional[Value]:

        # print("Debug get_value_that_strictly_satisfy")
        # from IPython import embed; embed(); exit()

        vars = set()

        for v in self.variables_alive:
            if v.get_type() == type:
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

        is_sink = self.is_sink(cond)

        val = None

        # for variables used in ret -> I take any compatible type and overwrite
        # their conditions
        if is_ret:

            # if I need a void for return, don't bother too much
            if type == self.stub_void:
                val = NullConstant(self.stub_void)
            else:
                val = self.randomly_gimme_a_var(type, "", is_ret)

        elif is_sink:
            val = self.get_value_that_strictly_satisfy(type, cond)
            if val is None:
                if (Conditions.is_unconstraint(cond) and 
                    not type.is_incomplete):
                    val = self.randomly_gimme_a_var(type, "", is_ret)
                else:
                    raise ConditionUnsat()
        elif self.has_var_type(type):
            val = self.get_value_that_satisfy(type, cond)
            if val is None:
                if (Conditions.is_unconstraint(cond) and 
                    not type.is_incomplete):
                    val = self.randomly_gimme_a_var(type, "", is_ret)
                else:
                    raise ConditionUnsat()
        else:
            if isinstance(type, PointerType):
                tt = type.get_pointee_type()  
            else:
                tt = type
            if tt.is_incomplete and not is_ret:
                raise ConditionUnsat()
            else:
                val = self.randomly_gimme_a_var(type, "", is_ret)

        if val == None:
            raise Exception("Val unset")

        return val

    def update(self, val: Optional[Value], cond: AccessTypeSet, is_ret: bool = False):

        if isinstance(val, NullConstant):
            # NullConstant does not have conditions
            return

        var = None
        if isinstance(val, Variable):
            # I am not sure it should be done here!
            x = AccessType(Access.WRITE, [])
            x2 = AccessTypeSet(set([x]))
            cond2 = cond.union(x2)
            var = val
        elif isinstance(val, Address):
            x = AccessType(Access.WRITE, [-1])
            x2 = AccessTypeSet(set([x]))
            cond2 = cond.union(x2)
            var = val.get_variable()
        else:
            raise Exception(f"I don't know this val: {val}")
            
        is_sink = self.is_sink(cond)

        if is_ret and var in self.variables_alive:
                del self.var_to_cond[var]
                self.variables_alive.remove(var)

        already_present = var in self.var_to_cond
        self.add_variable(var, cond)

        if already_present and is_sink:
            del self.var_to_cond[var]
            self.variables_alive.remove(var)

            # from IPython import embed; embed(); exit(1);
            # import pdb; pdb.set_trace(); exit(1);

    # NOTE: this oracle infers if the variable with the access types (cond) can
    # be considered a sink
    def is_sink(self, cond: AccessTypeSet):
        deletes_root = any([c.access == Access.DELETE and c.fields == [] 
                            for c in cond])
        creates_root = any([c.access == Access.CREATE and c.fields == [] 
                            for c in cond])
        return deletes_root and not creates_root

    def __copy__(self):
        raise Exception("__copy__ not implemented")
        
class ConditionUnsat(Exception):
    """ConditionUnsat, can't find a suitable variable in the RunningContext"""
    pass