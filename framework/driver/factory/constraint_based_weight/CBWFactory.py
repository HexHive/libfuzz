import copy
import random
import re
from typing import Set

from common import Api, FunctionConditionsSet
from constraints import ConditionManager
from dependency import DependencyGraph
from driver import Driver
from driver.factory.constraint_based import CBFactory
from driver.ir import ApiCall

class CBWFactory(CBFactory):
    
    def __init__(self, api_list: Set[Api], driver_size: int, 
                    dgraph: DependencyGraph, conditions: FunctionConditionsSet):
        super().__init__(api_list, driver_size, dgraph, conditions)

        self.api_initial_weigth = {}
        self.api_frequency = {}
        for a in self.dependency_graph.keys():
            self.api_initial_weigth[a] = len(self.get_reachable_apis(a))
            self.api_frequency[a] = 0

    def get_random_source_api(self):
        w = []
        for sa in self.source_api:
            w += [self.get_weigth(sa)]
        return random.choices(self.source_api, weights=w)[0]

    def get_random_candidate(self, candidate_api):
        w = []
        for ca in candidate_api:
            # Api object is in position 2
            w += [self.get_weigth(ca[2])]
        return random.choices(candidate_api, weights=w)[0]

    def get_weigth(self, api):

        if api not in self.api_frequency:
            self.api_frequency[api] = 0
            self.api_initial_weigth[api] = max([w for _, w in self.api_initial_weigth.items()])

        if self.api_frequency[api] == 0:
            return self.api_initial_weigth[api]
        
        return float(self.api_initial_weigth[api])/self.api_frequency[api]
    
    def set_api_frequency(self, api, freq):
        if api not in self.api_frequency:
            return
        self.api_frequency[api] = freq

    def get_api_frequency(self, api):
        if api not in self.api_frequency:
            return None
        return self.api_frequency[api]
    
    def upd_api_frequency(self, api, rel_freq):
        if api not in self.api_frequency:
            return
        self.api_frequency[api] += rel_freq

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
        d = super().create_random_driver()

        rel_freq = {}

        # update frequency
        for s in d.statements:
            if isinstance(s, ApiCall):
                api = s.original_api
                rel_freq[api] = rel_freq.get(api, 0) + 1

        for a, rf in rel_freq.items():
            self.upd_api_frequency(a, rf)

        return d
