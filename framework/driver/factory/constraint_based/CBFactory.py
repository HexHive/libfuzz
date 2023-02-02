import copy
import random
import re
from typing import Dict, List, Optional, Set, Tuple

from common import Api, FunctionConditionsSet, FunctionConditions
from constraints import Conditions, ConditionUnsat, RunningContext
from dependency import DependencyGraph
from driver import Context, Driver
from driver.factory import Factory
from driver.ir import ApiCall, BuffDecl, PointerType, Statement, Type, Variable


class CBFactory(Factory):
    api_list            : Set[Api]
    driver_size         : int
    # dependency_graph    : DependencyGraph
    conditions          : FunctionConditionsSet
    dependency_graph    : Dict[Api, Set[Api]]
    
    def __init__(self, api_list: Set[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet):
        self.api_list = api_list
        self.driver_size = driver_size
        # self.dependency_graph = dgraph
        self.conditions = conditions

        # DependencyGraph must be inverted, this is an "error". It probably
        # needs refactor in the future
        inv_dep_graph = dict((k, set()) for k in list(dgraph.keys()))
        for api, deps in dgraph.items():
            for dep in deps:
                if not dep in inv_dep_graph:
                    inv_dep_graph[dep] = set()
                
                inv_dep_graph[dep].add(api)
        self.dependency_graph = inv_dep_graph

    def get_starting_api(self) -> Set[Api]:
        starting_api = set()
        for api in self.api_list:
            if (not any(arg.is_type_incomplete for arg in api.arguments_info) and
                api.return_info.is_type_incomplete):
                starting_api.add(api)

        return starting_api

    def try_to_instantiate_api_call(self, api_call: ApiCall,
                        conditions: FunctionConditions, 
                        rng_ctx: RunningContext):

        # I prefer to have a local one
        rng_ctx = copy.deepcopy(rng_ctx)
        # context = rng_ctx.context

        unsat_vars = set()

        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_ats = conditions.argument_at[arg_pos]
            try:
                if rng_ctx.is_void_ponter(arg_type):
                    arg_var = rng_ctx.try_to_get_var(rng_ctx.stub_char_array, arg_ats)
                elif isinstance(arg_type, PointerType) and arg_type.to_function:
                    arg_var = rng_ctx.get_null_constant()
                else:
                    arg_var = rng_ctx.try_to_get_var(arg_type, arg_ats)
                api_call.set_pos_arg_var(arg_pos, arg_var)
            except ConditionUnsat:
                # print(f"got unsat, to handle 1!")
                unsat_vars.add((arg_pos, arg_ats))
        
        ret_ats = conditions.return_at
        ret_type = api_call.ret_type
        try:
            if rng_ctx.is_void_ponter(ret_type):
                ret_var = rng_ctx.try_to_get_var(rng_ctx.stub_char_array, ret_ats, True)
            elif isinstance(ret_type, PointerType) and ret_type.to_function:
                ret_var = rng_ctx.get_null_constant()
            else:
                ret_var = rng_ctx.try_to_get_var(ret_type, ret_ats, True)
            api_call.set_ret_var(ret_var)
        except ConditionUnsat:
            # print(f"got unsat, to handle 2!")
            unsat_vars.add((-1, ret_ats))
        
        if len(unsat_vars) != 0:
            return (None, unsat_vars)

        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_ats = conditions.argument_at[arg_pos]
            rng_ctx.update(api_call.arg_vars[arg_pos], arg_ats)
        if api_call.ret_var is not None:
            rng_ctx.update(api_call.ret_var, ret_ats)

        return (rng_ctx, unsat_vars)

    def create_random_driver(self) -> Driver:

        rng_ctx = RunningContext()

        # foo = self.api_list.pop()
        # foo_condition = self.conditions.get_function_conditions(foo.function_name)
        # call_foo = Factory.api_to_apicall(foo)

        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        starting_api = list(self.get_starting_api())

        # List[(ApiCall, RunningContext)]
        drv = list()

        begin_api = random.choice(starting_api)
        begin_condition = get_cond(begin_api)
        call_begin = to_api(begin_api)

        rng_ctx_1, unsat_var_1 = self.try_to_instantiate_api_call(call_begin, begin_condition, rng_ctx)

        # [next_possible] = [x for x in self.dependency_graph[begin_api] if x.function_name == "TIFFReadRGBAImage"]

        # next_condition = get_cond(next_possible)
        # call_next = to_api(next_possible)

        # rng_ctx_2, unsat_var_2 = self.try_to_instantiate_api_call(call_next, next_condition, rng_ctx_1) 

        # print("TOO LATE")
        # from IPython import embed; embed(); exit(1)

        if len(unsat_var_1) > 0:
            print("[ERROR] Cannot instantiate the first function :(")
            print(unsat_var_1)
            exit(1)

        drv += [(call_begin, rng_ctx_1)]

        api_n = begin_api
        while len(drv) < self.driver_size:

            # List[(ApiCall, RunningContext, Api)]
            candidate_api = []

            for next_possible in self.dependency_graph[api_n]:
                print(f"[INFO] Trying: {next_possible}")

                next_condition = get_cond(next_possible)
                call_next = to_api(next_possible)

                rng_ctx_2, unsat_var_2 = self.try_to_instantiate_api_call(call_next, next_condition, rng_ctx_1)      # type: ignore

                l_unsat_var = len(unsat_var_2)
                if l_unsat_var == 0:
                    print("[INFO] This works!")
                    candidate_api += [(call_next, rng_ctx_2, next_possible)]
                else:
                    print(f"[INFO] Unsat vars: {l_unsat_var}")
                    for p, c in unsat_var_2:
                        arg_type = call_next.arg_types[p]
                        print(f" => arg{p}: {arg_type} -> {c}")
                    print()

            print(f"[INFO] Complete doable functions: {len(candidate_api)}")

            if not candidate_api:
                from IPython import embed; embed(); exit(1)

            # (ApiCall, RunningContext, Api)
            (api_call, rng_ctx_1, api_n) = random.choice(candidate_api)

            drv += [(api_call, rng_ctx_1)]

        # print("after loop, debug exit..")
        # exit()

        # I want the last RunningContext
        context = [rng_ctx for _, rng_ctx in drv][-1]
        statements_apicall = [api_call for api_call, _ in drv]

        statements = []
        statements += context.generate_buffer_decl()
        statements += context.generate_buffer_init()
        statements += statements_apicall 

        # from IPython import embed; embed(); 
        # exit()

        return Driver(statements, context)