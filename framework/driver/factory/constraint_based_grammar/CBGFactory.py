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

from enum import IntEnum

class ApiSeqState(IntEnum):
    POSITIVE = 1
    NEGATIVE = 2
    UNKNOWN = 3
    def __str__(self):
        return str(self.name)

class CBGFactory(CBFactory):
    
    def __init__(self, api_list: Set[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet):
        super().__init__(api_list, driver_size, dgraph, conditions)

        # self.api_initial_weigth = {}
        # self.api_frequency = {}
        # for a in self.dependency_graph.keys():
        #     self.api_initial_weigth[a] = len(self.get_reachable_apis(a))
        #     self.api_frequency[a] = 0
            
        self.history_api_sequence = {}
        
        self.max_driver_size = 10

    def get_random_source_api(self):
        
        w = list()
        tmp_source_api = list()
        
        for sa in self.source_api:
            if sa.function_name in self.history_api_sequence:
                api_state, _ = self.history_api_sequence[sa.function_name]
            else:
                api_state = None
                
            if api_state == ApiSeqState.NEGATIVE:
                continue
            
            tmp_source_api += [(sa, None, None, None)]
            
        return self.get_random_candidate([], tmp_source_api)[0]
            
        # s_api = random.choices(tmp_source_api, weights=w)[0]
        # # self.inc_api_frequency(s_api)
        
        # return s_api
    
    def calc_seeds(self, driver, api_call):
        
        api_seq_str = self.calc_api_seq_str(driver, api_call)
        
        # sum_positive = 0
        # nun_negative = 0
        # tot_leafes = 0
        # for seq, (state, n_seeds) in self.history_api_sequence.items():
        #     if seq.startswith(api_seq_str):
                
        return self.history_api_sequence[api_seq_str][1]

    def get_random_candidate(self, driver, candidate_api):
        # w = []
        # for ca in candidate_api:
        #     # Api object is in position 2
        #     w += [self.get_weigth(ca[2])]
        
        positive_weights = []
        unknown_weights = []
        for call_next, x, y, api_state in candidate_api:
            if api_state == ApiSeqState.UNKNOWN:
                unknown_weights += [(call_next, x, y, api_state)]
            elif api_state == ApiSeqState.POSITIVE:
                n_seeds = self.calc_seeds(driver, call_next)
                positive_weights += [((call_next, x, y, api_state), n_seeds)]
            elif api_state == ApiSeqState.NEGATIVE:
                continue
            
        n_unk_weights = len(unknown_weights)
        n_pos_weights = len(positive_weights)
        
        if n_pos_weights > 0:
            
            sum_pos_weights = sum([w for _, w in positive_weights])
            
            prob_unkn = float(n_unk_weights)/(n_unk_weights+n_pos_weights)
            
            sum_unk_weights = prob_unkn/(1.0-prob_unkn)*sum_pos_weights
            
            candidate_api_new = positive_weights
            for u in unknown_weights:
                candidate_api_new += [(u, sum_unk_weights/n_unk_weights)]
            
            w = [ww for _, ww in candidate_api_new]
            candidate_api = [c for c, _ in candidate_api_new]
            r_api = random.choices(candidate_api, weights=w)[0] 
            return r_api
        else:
            w = [1 for _ in candidate_api]
            r_api = random.choices(candidate_api, weights=w)[0] 
            return r_api
            
    
    # def inc_api_frequency(self, api):
    #     freq = self.get_api_frequency(api)
    #     if freq is None:
    #         freq = 1
    #     else:
    #         freq = freq + 1
    #     self.set_api_frequency(api, freq)

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

    def get_reachable_apis(self, api):

        visited_api = set()
        working = [api]

        while(len(working) != 0):
            a = working.pop()
            for n in  self.dependency_graph[a]:
                if n in visited_api:
                    continue

                visited_api.add(n)
                working += [n]

        return visited_api

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

        min_driver_size = 8

        api_n = begin_api
        while len(drv) < self.max_driver_size:

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
                
                if api_state == ApiSeqState.UNKNOWN and len(drv) >= min_driver_size:
                    break
            else:
                if len(drv) >= min_driver_size:
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
        
        return api_seq_state