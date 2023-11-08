import random
from typing import Dict, List, Optional, Set, Tuple

from common import Api, FunctionConditionsSet
from constraints import RunningContext, ConditionManager
from dependency import DependencyGraph
from driver.factory.constraint_based import CBFactory
from driver.factory import Factory, EmptyDriverSpace
from driver.ir import PointerType, Variable, AllocType
from driver.ir import NullConstant, AssertNull, SetNull, Address, Variable

class CBSFactory(CBFactory):
    api_list            : Set[Api]
    driver_size         : int
    conditions          : FunctionConditionsSet
    dependency_graph    : Dict[Api, Set[Api]]
    condition_manager   : ConditionManager

    MAX_ALLOC_SIZE = 1024
    
    def __init__(self, api_list: Set[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet, weights: Dict[str,int]):
        super().__init__(api_list, driver_size, dgraph, conditions)

        self.api_initial_weigth = {}
        self.api_frequency = {}
        for a in self.dependency_graph.keys():
            fun_name = a.function_name
            self.api_initial_weigth[a] = weights[fun_name]
            # self.api_initial_weigth[a] = len(self.get_reachable_apis(a))
            # self.api_frequency[a] = 0

        # print("XXXX")
        # from IPython import embed; embed(); exit(1)

        # self.driver_generator = self.get_next_driver()

    def get_random_source_api(self):
        w = []
        for sa in self.source_api:
            w += [self.get_weigth(sa)]
        s_api = random.choices(self.source_api, weights=w)[0]
        # self.inc_api_frequency(s_api)
        return s_api

    def get_random_candidate(self, candidate_api):
        w = []
        for ca in candidate_api:
            # Api object is in position 2
            w += [self.get_weigth(ca[2])]
        r_api = random.choices(candidate_api, weights=w)[0] 
        # self.inc_api_frequency(r_api)
        return r_api
    
    # def inc_api_frequency(self, api):
    #     freq = self.get_api_frequency(api)
    #     if freq is None:
    #         freq = 1
    #     else:
    #         freq = freq + 1
    #     self.set_api_frequency(api, freq)

    def get_weigth(self, api):

        # if api not in self.api_frequency:
        #     # self.api_frequency[api] = 0
        #     self.api_initial_weigth[api] = max([w for _, w in self.api_initial_weigth.items()])

        # if self.api_frequency[api] == 0:
        return self.api_initial_weigth[api]
        
        # return float(self.api_initial_weigth[api])/self.api_frequency[api]
    
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

    # def get_api(self, function_name):
    #     all_function_name = [a.function_name for a in
    #                          self.dependency_graph.keys()]

    #     if function_name not in all_function_name:
    #         return None
        
    #     xx = [a for a in self.dependency_graph.keys() 
    #           if a.function_name == function_name]

    #     return xx[0]
    
    # def try_to_instantiate_chain(self, chain):

    #     rng_ctx = RunningContext()

    #     get_cond = lambda x: self.conditions.get_function_conditions(x.function_name)
    #     to_api = lambda x: Factory.api_to_apicall(x)

    #     inst_chain = []

    #     for api in chain:
                    
    #         api_condition = get_cond(api)
    #         api_call = to_api(api)

    #         rng_ctx, unsat_var_2 = self.try_to_instantiate_api_call(api_call, api_condition, rng_ctx)      # type: ignore

    #         l_unsat_var = len(unsat_var_2)
    #         if l_unsat_var == 0:
    #             inst_chain += [api_call]
    #         else:
    #             return {}
            
    #     return (inst_chain, rng_ctx)
    

    # target_list = ["foo", "bar", "zoo"]
    # source_list = ["s1", "s2"]

    # def generate_paths(source, target):
    #     for i in range(1, 10):
    #         # return f"path {i} from {source} to {target}"
    #         yield f"path {i} from {source} to {target}"

    # def next_driver():  

    #     for target in target_list:
    #         for source in source_list:
    #             g = generate_paths(source, target)
    #             for p in g:
    #                 yield p


    # def get_next_driver(self):
    #     for t_name, _ in self.weights:
    #         target = self.get_api(t_name)

    #         for source in self.source_api:

    #             try:
    #                 for path in nx.all_simple_paths(self.G, 
    #                                             source=source, 
    #                                             target=target, 
    #                                             cutoff=self.driver_size):
                    
    #                     a_chain = self.try_to_instantiate_chain(path)
    #                     if a_chain == {}:
    #                         continue

    #                     yield a_chain
    #             except:
    #                 continue

    #     raise EmptyDriverSpace()

    # def create_random_driver(self) -> Driver:

    #     drv, context = next(self.driver_generator)

    #     statements_apicall = []
    #     for api_call in drv:
    #         statements_apicall += [api_call]
    #         if (isinstance(api_call.ret_type, PointerType) and
    #             not isinstance(api_call.ret_var, NullConstant)):
    #             var = api_call.ret_var.get_variable()
    #             statements_apicall += [AssertNull(var.get_buffer())]
    #         # sink APIs have only 1 argument
    #         if self.condition_manager.is_sink(api_call):
    #             arg = api_call.arg_vars[0]
    #             if isinstance(arg, Address):
    #                 buff = arg.get_variable().get_buffer()
    #             elif isinstance(arg, Variable):
    #                 buff = arg.get_buffer()
    #             if buff.alloctype == AllocType.HEAP:
    #                 statements_apicall += [SetNull(buff)]

    #     context.generate_auxiliary_operations()

    #     statements = []
    #     statements += context.generate_buffer_decl()
    #     statements += context.generate_buffer_init()
    #     statements += statements_apicall 

    #     clean_up_sec = context.generate_clean_up()
    #     counter_size = context.get_counter_size()
    #     stub_functions = context.get_stub_functions()

    #     d = Driver(statements, context)
    #     d.add_clean_up(clean_up_sec)
    #     d.add_counter_size(counter_size)
    #     d.add_stub_functions(stub_functions)

    #     return d