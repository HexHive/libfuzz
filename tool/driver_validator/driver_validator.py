#!/usr/bin/env python3.11
PROJECT_FOLDER = "/workspaces/libfuzz"

import sys

sys.path.append(PROJECT_FOLDER)

import argparse
from framework import *
from framework.generator import Configuration
import logging

logging.getLogger().setLevel(logging.WARN)
logging.getLogger("validator").setLevel(logging.DEBUG)


import os, json, shutil, filecmp, tempfile
from subprocess import STDOUT, check_output
from typing import Set, Tuple, List, cast
import typing

import networkx as nx

from framework.driver.factory import Factory
from framework.driver.factory.constraint_based import CBFactory
from framework.driver.ir import ApiCall
from framework.constraints import RunningContext
from framework.driver import Context
from framework.common import Api, FunctionConditionsSet, FunctionConditions
from framework.dependency import DependencyGraph
from framework.generator import Configuration


def read_driver_graph() -> nx.MultiGraph:
    # TODO
    return nx.read_dot("")


class DriverNode:
    api_call: ApiCall
    def __init__(self, api_call) -> None:
        self.api_call = api_call

    def isRoot(self, graph: nx.DiGraph):
        roots = [n for n,d in graph.in_degree() if d == 0]
        print(len(roots))
        print(len(graph))
        return self in roots


def validate_node(
    driver_graph: nx.DiGraph,
    factory: CBFactory,
    node: DriverNode,
    fcs: FunctionConditionsSet,
    context: RunningContext,
) -> Tuple[bool, RunningContext | None]:
    print("hello")
    print(node)
    if node.isRoot(driver_graph):
        root_apis = factory.get_starting_api()
        print(root_apis)
        return (node.api_call in root_apis, RunningContext())
    else:
        new_ctx, unsat_vars = factory.try_to_instantiate_api_call(
            node.api_call,
            fcs.get_function_conditions(node.api_call.function_name),
            context,
        )
        return (new_ctx is None, new_ctx)


def validate_driver(driver_graph: nx.DiGraph, config: Configuration):
    factory: Factory = config.factory
    if typing.assert_type(factory, CBFactory):
        cbfactory = cast(CBFactory, factory)
        running_context: RunningContext = RunningContext()
        for node in driver_graph:
            res, context = validate_node(driver_graph, cbfactory, node, config.function_conditions, running_context)
            if not res:
              return False


def graph_init(config: Configuration) -> nx.DiGraph:
  api_list: List[Api] = list(config.api_list)
  assert(len(api_list) > 0)
  graph = nx.DiGraph()
  d_nodes = []
  root_dnode = None
  for x in api_list:
    d_node = DriverNode(x)
    if x.function_name == "TIFFOpen":
      graph.add_node(d_node)
      root_dnode = d_node
    d_nodes.append(d_node)
  graph.add_node(d_nodes[0])
  graph.add_node(d_nodes[1])
  graph.add_node(d_nodes[2])
  graph.add_edge(root_dnode, d_nodes[0])
  graph.add_edge(d_nodes[0], d_nodes[1])
  graph.add_edge(d_nodes[1], d_nodes[2])

  return graph


def __main():

    # default_config = "./targets/simple_connection/fuzz.json"
    default_config = PROJECT_FOLDER + "/targets/libtiff/generator.json"

    parser = argparse.ArgumentParser(description="Automatic Driver Generator")
    parser.add_argument(
        "--config", type=str, help="The configuration", default=default_config
    )

    args = parser.parse_args()

    config = Configuration(args.config)

    fcs = config.function_conditions

    print(fcs)
    graph = graph_init(config)
    validate_driver(graph, config)


if __name__ == "__main__":
    __main()
