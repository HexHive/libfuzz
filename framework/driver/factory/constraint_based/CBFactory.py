import copy
import random
from typing import Dict, List, Optional, Set, Tuple

from common import Api, FunctionConditionsSet, FunctionConditions, DataLayout
from constraints import ConditionUnsat, RunningContext, ConditionManager
from dependency import DependencyGraph
from driver import Driver
from driver.factory import Factory
from driver.ir import ApiCall, PointerType, Variable, AllocType
from driver.ir import NullConstant, AssertNull, SetNull, Address, Variable


class CBFactory(Factory):
    api_list            : Set[Api]
    driver_size         : int
    conditions          : FunctionConditionsSet
    dependency_graph    : Dict[Api, Set[Api]]
    condition_manager   : ConditionManager
    
    def __init__(self, api_list: Set[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet):
        self.api_list = api_list
        self.driver_size = driver_size
        # self.dependency_graph = dgraph
        self.conditions = conditions

        # I need this to build synthetic constraints in "update" method
        RunningContext.type_to_hash = {}
        for f, c in self.conditions:
            for arg in c.argument_at + [c.return_at]:
                for at in arg.ats:
                    RunningContext.type_to_hash[at.type_string] = at.type

        # DependencyGraph must be inverted, this is an "error". It probably
        # needs refactor in the future
        inv_dep_graph = dict((k, set()) for k in list(dgraph.keys()))
        for api, deps in dgraph.items():
            for dep in deps:
                if not dep in inv_dep_graph:
                    inv_dep_graph[dep] = set()
                
                inv_dep_graph[dep].add(api)
        self.dependency_graph = inv_dep_graph

        self.condition_manager = ConditionManager.instance()

        self.source_api = list(self.condition_manager.get_source_api())

        self.init_api = self.condition_manager.get_init_api()

        # print(self.init_api)
        # print("TEST INIT APIS")
        # from IPython import embed; embed(); exit(1)

    attempt = 3

    def try_to_instantiate_api_call(self, api_call: ApiCall,
                        conditions: FunctionConditions, 
                        rng_ctx: RunningContext):
        # I prefer to have a local one
        rng_ctx = copy.deepcopy(rng_ctx)
        # context = rng_ctx.context

        # fun_name = api_call.function_name

        unsat_vars = set()

        # first round to initialize dependency args
        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_cond = conditions.argument_at[arg_pos]
            #  TODO: add and test if it works
            #  and not isinstance(arg_type, PonterType)
            if arg_cond.len_depends_on != "":
                idx = int(arg_cond.len_depends_on.replace("param_", ""))
                idx_type = api_call.arg_types[idx]

                if DataLayout.instance().is_enum_type(idx_type.get_token()):
                    arg_cond.len_depends_on = ""
                elif isinstance(idx_type, PointerType):
                    arg_cond.len_depends_on = ""
                else:
                    
                    if (isinstance(arg_type, PointerType) and 
                        arg_type.get_pointee_type() == rng_ctx.stub_void):
                        arg_var = rng_ctx.create_new_var(
                            rng_ctx.stub_char_array, arg_cond, False)
                    else:
                        arg_var = rng_ctx.create_new_var(
                            arg_type, arg_cond, False)
                        
                    x = arg_var
                    if (isinstance(arg_var, Variable) and 
                        isinstance(arg_type, PointerType)):
                        arg_var = arg_var.get_address()
                    api_call.set_pos_arg_var(arg_pos, arg_var)

                    # idx = int(arg_cond.len_depends_on.replace("param_", ""))
                    # idx_type = api_call.arg_types[idx]
                    idx_cond = conditions.argument_at[idx]
                    b_len = rng_ctx.create_new_var(idx_type, idx_cond, False)
                    try:
                        api_call.set_pos_arg_var(idx, b_len)
                    except:
                        print("Exception here")
                        from IPython import embed; embed(); exit(1)

                    rng_ctx.update(api_call, arg_cond, arg_pos)
                    rng_ctx.update(api_call, idx_cond, idx)
                    rng_ctx.var_to_cond[x].len_depends_on = b_len

        # if api_call.function_name == "htp_connp_create" and self.attempt > 0:
        #     self.attempt -= 1

        # if api_call.function_name == "pcap_geterr":
        #     print(f"hook {api_call.function_name}")
        #     # import pdb; pdb.set_trace()
        #     par_debug = -1
        #     arg_pos = par_debug
        #     is_ret = True
        #     # arg_type = api_call.arg_types[par_debug]
        #     # arg_cond = conditions.argument_at[par_debug]
        #     arg_type = api_call.ret_type
        #     arg_cond = conditions.return_at
        #     type = arg_type
        #     tt = type.get_pointee_type()
        #     cond = conditions.argument_at[par_debug]
        #     from IPython import embed; embed(); exit(1)

        # second round to initialize all the other args
        for arg_pos, arg_type in api_call.get_pos_args_types():
            arg_cond = conditions.argument_at[arg_pos]

            if api_call.arg_vars[arg_pos] is not None:
                continue

            try:
                if isinstance(arg_type, PointerType) and arg_type.to_function:
                    # arg_var = rng_ctx.get_null_constant()
                    arg_var = rng_ctx.get_function_pointer(arg_type)
                else:
                    # arg_var = rng_ctx.try_to_get_var(arg_type, arg_cond, 
                    #                                  fun_name, conditions, 
                    #                                  arg_pos)
                    arg_var = rng_ctx.try_to_get_var(api_call, conditions, 
                                                     arg_pos)
                api_call.set_pos_arg_var(arg_pos, arg_var)
            except ConditionUnsat as ex:
                # if api_call.function_name == "vpx_codec_decode" and self.attempt == 0:
                #     print(f"Unsat for {api_call.function_name}")
                #     from IPython import embed; embed(); exit(1)
                # self.attempt -= 1
                unsat_vars.add((arg_pos, arg_cond))
        
        ret_cond = conditions.return_at
        ret_type = api_call.ret_type
        try:
            if isinstance(ret_type, PointerType) and ret_type.to_function:
                ret_var = rng_ctx.get_null_constant()
            else:
                # ret_var = rng_ctx.try_to_get_var(ret_type, ret_cond,
                #                                  fun_name, conditions,
                #                                  -1)
                ret_var = rng_ctx.try_to_get_var(api_call, conditions, -1)
            api_call.set_ret_var(ret_var)
        except ConditionUnsat:
            unsat_vars.add((-1, ret_cond))
        
        if len(unsat_vars) != 0:
            return (None, unsat_vars)

        for arg_pos, arg_type in api_call.get_pos_args_types():
            rng_ctx.update(api_call, arg_cond, arg_pos)

        if api_call.ret_var is not None:
            rng_ctx.update(api_call, ret_cond, -1)

        # I might have other pending vars to include
        # e.g., for controlling arrays length
        for var, var_len, cond_len in rng_ctx.new_vars:
            rng_ctx.update_var(var_len, cond_len)
            rng_ctx.var_to_cond[var].len_depends_on = var_len
        rng_ctx.new_vars.clear()

        return (rng_ctx, {})
    
    def get_random_source_api(self):
        return random.choice(self.source_api)

    def get_random_candidate(self, candidate_api):
        return random.choice(candidate_api)

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

        # print("after create_random_driver")
        # from IPython import embed; embed(); exit(1)

        api_n = begin_api
        while len(drv) < self.driver_size:

            # List[(ApiCall, RunningContext, Api)]
            candidate_api = []

            if api_n in self.dependency_graph:
                for next_possible in self.dependency_graph[api_n]:

                    if next_possible in self.source_api:
                        continue

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
                (api_call, rng_ctx_1, api_n) = self.get_random_candidate(candidate_api)
                print(f"[INFO] choose {api_call.function_name}")

                # if api_call.function_name == "TIFFReadRGBAImage":
                #     from IPython import embed; embed(); exit(1)

                drv += [(api_call, rng_ctx_1)]
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

        return d