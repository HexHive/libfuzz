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
        return Driver([], context)