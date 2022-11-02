import random, copy, re
from typing import List, Set, Dict, Tuple, Optional

from dependency import DependencyGraph

from common import Utils, Api, Arg

from driver import Driver, Context
from driver.factory import Factory
from driver.ir import Statement, ApiCall, BuffDecl, Type, PointerType, Variable

class CBFactory(Factory):
    
    
    def __init__(self, api_list, driver_size, dgraph: DependencyGraph):
        self.api_list = api_list
        self.driver_size = driver_size
        self.dependency_graph = dgraph

    def create_random_driver(self) -> Driver:
        context = Context()
        return Driver([], context)