import copy
import random
import re
from typing import Set

from common import Api, FunctionConditionsSet
from constraints import ConditionUnsat, RunningContext, ConditionManager
from dependency import DependencyGraph
from driver import Driver
from driver.factory.constraint_based import CBFactory
from driver.factory import Factory
from driver.ir import ApiCall, PointerType, Variable, AllocType, Constant
from driver.ir import NullConstant, AssertNull, SetNull, Address, Variable

import json

from enum import IntEnum

import numpy as np

class ApiSeqState(IntEnum):
    POSITIVE = 1
    NEGATIVE = 2
    UNKNOWN = 3
    def __str__(self):
        return str(self.name)

# Sigmoid function
def sigmoid(x):
    return 1 / (1 + np.exp(-x))

class CBGFactory(CBFactory):
    
    def __init__(self, api_list: Set[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet, 
                    number_of_unknown: int):
        super().__init__(api_list, driver_size, dgraph, conditions)
            
        self.history_api_sequence = {}
        
        self.number_of_unknown = number_of_unknown
        
        self.n_driver = 0
        
    def dump_log_2(self, source_api):
        with open("source_weight_logs.json", "w") as fp:
            
            candidates = list()
            for i, c in enumerate(source_api):
                rc = {}
                
                rc["function_name"] = c[0].function_name # function name
                rc["state"] = f"{c[3]}" # state
                
                # num. seed
                if c[3] == ApiSeqState.POSITIVE:
                    rc["seeds"] = self.calc_seeds([], c[0]) 
                else:
                    rc["seeds"] = 0
                    
                rc["ats"] = self.calc_ast(c[0])
                
                # rc["weight"] = weights[i] # weight
                
                candidates += [rc]
                
            json.dump(candidates, fp, indent=4, sort_keys=True)
            
            # if len(driver) == 1:
            #     print("dump_log")
            #     from IPython import embed; embed(); exit(1)
        
    def dump_log(self, driver, candidate_api, weights):
        with open("weight_logs.txt", "a") as fp:
            
            r = {}
            r["driver_name"] = f"driver{self.n_driver}"
            
            r["driver"] = ";".join([d[0].function_name for d in driver])
            
            candidates = []
            for i, c in enumerate(candidate_api):
                rc = {}
                
                rc["function_name"] = c[0].function_name # function name
                rc["state"] = f"{c[3]}" # state
                
                # num. seed
                if c[3] == ApiSeqState.POSITIVE:
                    rc["seeds"] = self.calc_seeds(driver, c[0]) 
                else:
                    rc["seeds"] = 0
                
                rc["weight"] = weights[i] # weight
                
                candidates += [rc]
                
            r["candidates"] = candidates
            
            # if len(driver) == 1:
            #     print("dump_log")
            #     from IPython import embed; embed(); exit(1)
                
            fp.write(json.dumps(r) + "\n")

        
    def get_random_source_api(self):
        
        w = list()
        tmp_source_api = list()
        
        for sa in self.source_api:
            if sa.function_name in self.history_api_sequence:
                api_state, _ = self.history_api_sequence[sa.function_name]
            else:
                api_state = ApiSeqState.UNKNOWN
                
            if api_state == ApiSeqState.NEGATIVE:
                continue
            
            tmp_source_api += [(sa, None, None, api_state)]
            
        # self.dump_log_2(tmp_source_api)
            
        return self.get_random_candidate([], tmp_source_api)[0]
        
    def get_ast(self, api_call: ApiCall):
        
        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        
        fc = get_cond(api_call)
        
        ats = {}
        
        rt = api_call.ret_type
        if isinstance(rt, PointerType):
            rt = rt.get_base_type()
        ats[rt] = set([".".join([f"{f}" for f in at.fields]) for at in fc.return_at.ats.access_type_set])
        
        # ats += [len(fc.return_at.ats.access_type_set)]
        
        for a, arg_c in enumerate(fc.argument_at):
            # ats += [len(arg.ats.access_type_set)]
            at = api_call.arg_types[a]
            if isinstance(at, PointerType):
                at = at.get_base_type()
                
            t_fields = ats.get(at, set())
            t_fields |= set([".".join([f"{f}" for f in at.fields]) for at in arg_c.ats.access_type_set])
            ats[at] = t_fields 
            
        return ats
        
    def calc_ast(self, api_call):
        
        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        
        fc = get_cond(api_call)
        
        ats = list()
        
        ats += [len(fc.return_at.ats.access_type_set)]
        
        for arg in fc.argument_at:
            ats += [len(arg.ats.access_type_set)]
            
        return sum(ats)
    
    def calc_seeds(self, driver, api_call):
        
        api_seq_str = self.calc_api_seq_str(driver, api_call)
        
        ok_seq = {}
        
        for seq, val in self.history_api_sequence.items():
            if seq.startswith(api_seq_str): # and val[0] == ApiSeqState.POSITIVE:
                ok_seq[seq] = val[1]
            
            
        ok_seq_save = ok_seq
            
        while True:
            ok_seq_new = {}
            
            for s1, v1 in ok_seq.items():
                has_longer = False
                for s2, _ in ok_seq.items():
                    if s1 == s2: 
                        continue
                    
                    if s2.startswith(s1):
                        has_longer = True
                        break
                if not has_longer:
                    ok_seq_new[s1] = v1
                    
            # Fix point: I reach the minimum set
            if ok_seq.keys() == ok_seq_new.keys():
                break
            
            ok_seq = ok_seq_new
            
        
        # if len(ok_seq_save) >= 3:
        #     print("calc_seeds..")
        #     from IPython import embed; embed(); exit(1)
            
        n_seq = len(ok_seq)
        sum_seeds = sum([v for _, v in ok_seq.items()])
            
        return np.arctan(sum_seeds/n_seq)
        
        # sum_positive = 0
        # nun_negative = 0
        # tot_leafes = 0
        # for seq, (state, n_seeds) in self.history_api_sequence.items():
        #     if seq.startswith(api_seq_str):
                
        # return self.history_api_sequence[api_seq_str][1]

    def get_random_candidate(self, driver, candidate_api):
        
        if driver is None or len(driver) == 0:
            
            candidate_api_new = []
            for call_next, x, y, api_state in candidate_api:
                if api_state == ApiSeqState.UNKNOWN or api_state is None:
                    n_ast = self.calc_ast(call_next)
                    candidate_api_new += [((call_next, x, y, api_state), n_ast)]
                elif api_state == ApiSeqState.POSITIVE:
                    n_ast = self.calc_ast(call_next)
                    candidate_api_new += [((call_next, x, y, api_state), n_ast)]
                elif api_state == ApiSeqState.NEGATIVE:
                    continue
                
            w = [ww for _, ww in candidate_api_new]
            candidate_api = [c for c, _ in candidate_api_new]
            r_api = random.choices(candidate_api, weights=w)[0] 
            return r_api
        
        else:
            
            last_apicall = driver[-1][0]
            
            last_apicall_ats = self.get_ast(last_apicall)
            
            # from IPython import embed; embed(); exit
            
            candidate_api_new = []
            for call_next, x, y, api_state in candidate_api:
                if api_state == ApiSeqState.UNKNOWN or api_state is None:
                    # n_ast = self.calc_ast(call_next)
                    n_ast = self.get_ast(call_next)
                    
                    common_fields = 0
                    for ct in n_ast.keys() & last_apicall_ats.keys():
                        common_fields += len(n_ast[ct] & last_apicall_ats[ct])                    
                    
                    candidate_api_new += [((call_next, x, y, api_state), common_fields)]
                elif api_state == ApiSeqState.POSITIVE:
                    
                    # n_ast = self.calc_ast(call_next)
                    n_ast = self.get_ast(call_next)
                    
                    common_fields = 0
                    for ct in n_ast.keys() & last_apicall_ats.keys():
                        common_fields += len(n_ast[ct] & last_apicall_ats[ct])
                    
                    candidate_api_new += [((call_next, x, y, api_state), common_fields)]
                    
                elif api_state == ApiSeqState.NEGATIVE:
                    continue
                
            w = [ww for _, ww in candidate_api_new]
            if sum(w) == 0:
                w = [1 for _, _ in candidate_api_new]
            candidate_api = [c for c, _ in candidate_api_new]
            r_api = random.choices(candidate_api, weights=w)[0] 
            return r_api
            
        
        return []
        
        # NOTE: do not delete this part below, it is an important piece of my mind
        # candidate_api_new = []
        # for call_next, x, y, api_state in candidate_api:
        #     if api_state == ApiSeqState.UNKNOWN or api_state is None:
        #         n_ast = self.calc_ast(call_next)
        #         candidate_api_new += [((call_next, x, y, api_state), n_ast)]
        #     elif api_state == ApiSeqState.POSITIVE:
        #         # NOTE: this is for using seeds as weight
        #         # n_seeds = self.calc_seeds(driver, call_next)
        #         n_ast = self.calc_ast(call_next)
        #         candidate_api_new += [((call_next, x, y, api_state), n_ast)]
        #     elif api_state == ApiSeqState.NEGATIVE:
        #         continue
            
        # w = [ww for _, ww in candidate_api_new]
        # candidate_api = [c for c, _ in candidate_api_new]
        # r_api = random.choices(candidate_api, weights=w)[0] 
        # # self.dump_log(driver, candidate_api, w)
        # return r_api
        # NOTE: do not delete till HERE!!

    def get_weigth(self, drv, api):

        if api not in self.api_frequency:
            self.api_frequency[api] = 0
            self.api_initial_weigth[api] = max([w for _, w in self.api_initial_weigth.items()])

        if self.api_frequency[api] == 0:
            return self.api_initial_weigth[api]
        
        return float(self.api_initial_weigth[api])/self.api_frequency[api]
    
    # def set_api_frequency(self, api, freq):
    #     if api not in self.api_frequency:
    #         return
    #     self.api_frequency[api] = freq

    # def get_api_frequency(self, api):
    #     if api not in self.api_frequency:
    #         return None
    #     return self.api_frequency[api]
    
    # def upd_api_frequency(self, api, rel_freq):
    #     if api not in self.api_frequency:
    #         return
    #     self.api_frequency[api] += rel_freq

    # def get_reachable_apis(self, api):

    #     visited_api = set()
    #     working = [api]

    #     while(len(working) != 0):
    #         a = working.pop()
    #         for n in  self.dependency_graph[a]:
    #             if n in visited_api:
    #                 continue

    #             visited_api.add(n)
    #             working += [n]

    #     return visited_api

    def create_random_driver(self) -> Driver:

        rng_ctx = RunningContext()

        # foo = self.api_list.pop()
        # foo_condition = self.conditions.get_function_conditions(foo.function_name)
        # call_foo = Factory.api_to_apicall(foo)

        get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
        to_api = lambda x: Factory.api_to_apicall(x)

        if len(self.source_api) == 0:
            raise Exception("I cannot find APIs to begin with :(")

        # List[(ApiCall, RunningContext)]
        drv = list()

        # print("Instantiate the first source api")
        # print("inspect: ares_parse_a_reply")
        # from IPython import embed; embed(); exit(1)

        begin_api = self.get_random_source_api()
        begin_condition = get_cond(begin_api)
        call_begin = to_api(begin_api)

        rng_ctx_1, unsat_var_1 = self.try_to_instantiate_api_call(
            call_begin, begin_condition, rng_ctx)

        if len(unsat_var_1) > 0:
            print("[ERROR] Cannot instantiate the first function [first] :(")
            print(unsat_var_1)
            from IPython import embed; embed(); exit(1)
            exit(1)

        print(f"[INFO] starting with {call_begin.function_name}")
        drv += [(call_begin, rng_ctx_1)]
        
        # print(f"after {call_begin.function_name}")
        # from IPython import embed; embed(); exit(1)
        
        if self.calc_api_state(drv) != ApiSeqState.UNKNOWN:

            left_accepted_unknown = self.number_of_unknown

            api_n = begin_api
            while len(drv) < self.driver_size:

                # List[(ApiCall, RunningContext, Api, ApiSeqState)]
                candidate_api = []

                if api_n in self.dependency_graph:
                    for next_possible in self.dependency_graph[api_n]:

                        if next_possible in self.source_api:
                            continue
                    
                        # if next_possible in self.init_api:
                        #     continue
                        
                        # print("[INFO] Again...")
                        
                        api_state = self.calc_api_state(drv, next_possible)
                        # print(f"[INFO] Get API State: {api_state}")
                        if api_state == ApiSeqState.NEGATIVE:
                            # print("[INFO] skip")
                            continue
                        
                        # if next_possible.function_name == "TIFFGetField":
                        #     print("[INFO] double check api_state")
                        #     from IPython import embed; embed()
                        #     print("[INFO] doesn't matter...")
                        
                        # print("[INFO] continue...")

                        print(f"[INFO] Trying: {next_possible}")

                        next_condition = get_cond(next_possible)
                        call_next = to_api(next_possible)

                        rng_ctx_2, unsat_var_2 = self.try_to_instantiate_api_call(call_next, next_condition, rng_ctx_1)      # type: ignore

                        l_unsat_var = len(unsat_var_2)
                        if l_unsat_var == 0:
                            print("[INFO] This works!")
                            candidate_api += [(call_next, rng_ctx_2, next_possible, api_state)]
                        else:
                            print(f"[INFO] Unsat vars: {l_unsat_var}")
                            for p, c in unsat_var_2:
                                arg_type = call_next.arg_types[p]
                                print(f" => arg{p}: {arg_type} -> {c}")

                print(f"[INFO] Complete doable functions: {len(candidate_api)}")

                # if api_n.function_name == "TIFFWarning":
                #     print("next to close?")
                #     from IPython import embed; embed(); exit(1)

                # this check avoids the driver to degenerate in a list with a single
                # API repetitively invoked
                if len(candidate_api) == 1 and candidate_api[0][2] == api_n:
                    candidate_api = []
                    
                if candidate_api:
                    # (ApiCall, RunningContext, Api)
                    (api_call, rng_ctx_1, api_n, api_state) = self.get_random_candidate(drv, candidate_api)
                    print(f"[INFO] choose {api_call.function_name}")

                    # if api_call.function_name == "TIFFReadRGBAImage":
                    #     from IPython import embed; embed(); exit(1)

                    drv += [(api_call, rng_ctx_1)]
                    
                    if api_state == ApiSeqState.UNKNOWN:
                        if left_accepted_unknown == 0:
                            break
                        else:
                            left_accepted_unknown = left_accepted_unknown - 1
                        
                else:
                    # break
                    if left_accepted_unknown == 0:
                        break
                    else:
                        api_n = self.get_random_source_api()
                        begin_condition = get_cond(api_n)
                        call_begin = to_api(api_n)

                        print(f"[INFO] starting new chain with {api_n.function_name}")

                        rng_ctx_1, unsat_var_1 = self.try_to_instantiate_api_call(call_begin, begin_condition, rng_ctx_1)

                        if len(unsat_var_1) > 0:
                            print("[ERROR] Cannot instantiate the first function [second] :(")
                            print(unsat_var_1)
                            from IPython import embed; embed(); exit(1)
                            exit(1)

                        drv += [(call_begin, rng_ctx_1)]
                        
                        left_accepted_unknown = left_accepted_unknown - 1
                
            # print("after loop, debug exit..")
            # exit()

        # I want the last RunningContext
        context = [rng_ctx for _, rng_ctx in drv][-1]

        statements_apicall = []
        for api_call, _ in drv:
            statements_apicall += [api_call]
            if (isinstance(api_call.ret_type, PointerType) and
                not isinstance(api_call.ret_var, NullConstant)):
                var = api_call.ret_var.get_variable()
                statements_apicall += [AssertNull(var.get_buffer())]
            cond = get_cond(api_call)
            # for cond_pos, cond_arg in enumerate(cond.argument_at):
            # sink APIs have only 1 argument
            if self.condition_manager.is_sink(api_call):
                arg = api_call.arg_vars[0]
                if isinstance(arg, Address):
                    buff = arg.get_variable().get_buffer()
                elif isinstance(arg, Variable):
                    buff = arg.get_buffer()
                if buff.alloctype == AllocType.HEAP:
                    statements_apicall += [SetNull(buff)]
            # if RunningContext.is_sink(api_call.ret_type, PointerType):

        # print("Before ")
        # from IPython import embed; embed(); 
        # exit()

        context.generate_auxiliary_operations()

        statements = []
        statements += context.generate_buffer_decl()
        statements += context.generate_buffer_init()
        statements += statements_apicall 

        clean_up_sec = context.generate_clean_up()
        counter_size = context.get_counter_size()
        stub_functions = context.get_stub_functions()

        d = Driver(statements, context)
        d.add_clean_up(clean_up_sec)
        d.add_counter_size(counter_size)
        d.add_stub_functions(stub_functions)
        
        d.statements_apicall = drv

        self.n_driver = self.n_driver + 1
        return d
    
    def calc_api_seq_str(self, driver, api = None) -> str:
        
        api_seq = []
        for s in driver:
            api_seq += [s[0].original_api.function_name]
        api_seq_str = ";".join(api_seq)
        
        if api is not None:
            if api_seq_str == "":
                api_seq_str += f"{api.function_name}"
            else:
                api_seq_str += f";{api.function_name}"
                
        return api_seq_str


    def calc_api_state(self, driver, api = None):
        
        api_seq_str = self.calc_api_seq_str(driver, api)
        
        if api_seq_str not in self.history_api_sequence:
            return ApiSeqState.UNKNOWN
        
        return self.history_api_sequence[api_seq_str][0]
    
    def update_api_state(self, driver, api_seq_state, n_seeds) -> ApiSeqState:
        
        api_seq_str = self.calc_api_seq_str(driver)
        
        self.history_api_sequence[api_seq_str] = (api_seq_state, n_seeds)
        
        # print("update_api_state")
        # from IPython import embed; embed(); exit(1)
        
        return api_seq_state
