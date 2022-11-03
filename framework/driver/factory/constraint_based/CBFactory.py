import random, copy, re
from typing import List, Set, Dict, Tuple, Optional

from dependency import DependencyGraph

from common import Api, FunctionConditionsSet

from driver import Driver, Context
from driver.factory import Factory
from driver.ir import Statement, ApiCall, BuffDecl, Type, PointerType, Variable

class CBFactory(Factory):
    api_list    : List[Api]
    driver_size : int
    dgraph      : DependencyGraph
    conditions  : FunctionConditionsSet
    
    def __init__(self, api_list: List[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet):
        self.api_list = api_list
        self.driver_size = driver_size
        self.dependency_graph = dgraph
        self.conditions = conditions

    def create_random_driver(self) -> Driver:
        context = Context()

        starting_api = set()
        for api in self.api_list:
            if (not any(arg.is_type_incomplete for arg in api.arguments_info) and
                api.return_info.is_type_incomplete):
                starting_api.add(api)

        print(f"#APIs: {len(self.api_list)}")
        print(f"#APIs to start: {len(starting_api)}")

        # print(starting_api)

        begin_api = [a for a in starting_api if a.function_name=="TIFFClientOpen"][0]

        print(begin_api)
        # print("Which API I might start with?")
        # for api in starting_api:
        #     print(f"{api}")

        begin_ret_info = begin_api.return_info.type

        print("Candidate next:")
        for api in self.dependency_graph.graph[begin_api]:
            if any(arg.type == begin_ret_info for arg in api.arguments_info):
                print(api)

        from IPython import embed; embed()

        exit()

        return Driver([], context)