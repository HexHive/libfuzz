import json

from dependency import DependencyGraph
from common import Api

class TypeDependencyGraph(DependencyGraph):
    
    def __init__(self):
        self.graph = {}

    def addEdge(self, api_from: Api, api_to: Api):
        api_a_depdences = self.graph.get(api_from, [])
        api_a_depdences += [api_to]
        self.graph[api_from] = api_a_depdences