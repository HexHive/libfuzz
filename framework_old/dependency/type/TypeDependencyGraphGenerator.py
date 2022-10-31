import json, os

from common import Utils, Api, Arg
from dependency import DependencyGraphGenerator, DependencyGraph

class TypeDependencyGraphGenerator(DependencyGraphGenerator):
    def __init__(self, api_list):
        super().__init__()
        self.apis_list = api_list

    def create(self) -> DependencyGraph:
        dependency_graph = DependencyGraph()
        for api_a in self.apis_list:
            for api_b in self.apis_list:
                api_a_functionname = api_a.function_name
                api_b_functionname = api_b.function_name
                if self.dependency_on(api_a, api_b):
                    dependency_graph.add_edge(api_a, api_b)
                    # api_a_depdences = dependency_graph.get(api_a_functionname, [])
                    # api_a_depdences += [api_b_functionname]
                    # dependency_graph[api_a_functionname] = api_a_depdences

        return dependency_graph

    def dependency_on(self, api_a: Api, api_b: Api):

        api_a_functionname = api_a.function_name
        api_b_functionname = api_b.function_name
        input_a, output_a = self.get_input_output(api_a)
        input_b, output_b = self.get_input_output(api_b)

        # print("-"*30)

        # print(f"does '{api_a_functionname}' depends on '{api_b_functionname}'?")
        # print(f"input {input_a}")
        # print(f"output {output_a}")

        # print()

        # print(f"input {input_b}")
        # print(f"output {output_b}")

        intersection_ina_outb = self.intersection_args(input_a, output_b)

        # print(f"intersection_ina_outb")
        # print(intersection_ina_outb)
        # print()

        return len(intersection_ina_outb) != 0

    
    def get_input_output(self, api: Api):
        input_a = []
        output_a = [api.return_info]
        # print(api.arguments_info)
        for arg in api.arguments_info:
            if arg.flag == "ref":
                output_a += [arg]
            
            input_a += [arg]

        return input_a, output_a

    def intersection_args(self, args_a, args_b):

        intersection_set = set()
        for arg_a in args_a:
            for arg_b in args_b:
                type_match = arg_a.type.replace("*", "") == arg_b.type.replace("*", "")
                size_match = arg_a.size == arg_b.size

                if type_match: # or size_match:
                    intersection_set.add((arg_a.name, arg_b.name))

        return intersection_set

#     print("Dependency graph")
#     for f, ds in dependency_graph.items():
#         d_str = ", ".join(ds)
#         print(f"{f} depends on: {d_str}")

#     plot_graph(dependency_graph)

#     with open("dependency_graph.json", "w") as f:
#         json.dump(dependency_graph, f, indent=4, sort_keys=True)
