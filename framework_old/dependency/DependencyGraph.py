import json
from abc import ABC, abstractmethod

from common import Api

class DependencyGraph(ABC):
    def __init__(self):
        self.graph = {}

    def add_edge(self, api_from: Api, api_to: Api):
        api_a_depdences = self.graph.get(api_from, [])
        api_a_depdences += [api_to]
        self.graph[api_from] = api_a_depdences

    def keys(self):
        return self.graph.keys()

    def items(self):
        return self.graph.items()