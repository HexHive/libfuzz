#!/usr/bin/env python3.11
PROJECT_FOLDER = "/workspaces/libfuzz"

import sys

sys.path.append(PROJECT_FOLDER)

import argparse
from termcolor import colored
from framework import *
from framework.generator import Configuration
import logging

logging.basicConfig(level=logging.WARN)
logging.getLogger("validator").setLevel(logging.DEBUG)

from typing import List, cast
import typing

import networkx as nx

from framework.driver.factory.constraint_based import CBFactory
from framework.driver.ir import ApiCall
from framework.constraints import RunningContext, ConditionUnsat
from framework.common import Api, FunctionConditionsSet
from framework.generator import Configuration

my_logger = logging.getLogger("validator")


def read_driver_graph() -> nx.MultiGraph:
    """Read and parse a dotfile of a driver CFG representation.

    Returns:
        nx.MultiGraph: A directed graph with each node representing a function
                       call and each edge a possible control flow.
    """
    # TODO
    return nx.read_dot("")


class DriverNode:
    api_call: ApiCall

    def __init__(self, api_call: ApiCall) -> None:
        self.api_call = api_call

    def isRoot(self, graph: nx.DiGraph) -> bool:
        """Check if the node is at the first function call of a driver by looing
           at the incoming edges

        Args:
            graph (nx.DiGraph): CFG of the driver

        Returns:
            bool:
        """
        roots = [n for n, d in graph.in_degree() if d == 0]
        return self in roots


def validate_node(
    node: DriverNode,
    context: RunningContext,
    driver_graph: nx.DiGraph,
    factory: CBFactory,
    fcs: FunctionConditionsSet,
) -> RunningContext | None:
    """Based on the current running context, this function checks if 'node'
       could be added to such a driver with such a context

    Args:
        node (DriverNode): node to be added
        context (RunningContext): context generated from previous call. Empty
                                  if first ApiCall
        driver_graph (nx.DiGraph): the graph from which the node is part of
        factory (CBFactory): the ConstraintBased factory to validate
        fcs (FunctionConditionsSet): the conditions imposed by the different
                                     function calls

    Returns:
        RunningContext | None: None in case we can't validate the node. The
                               updated RunningContext otherwise
    """
    if node.isRoot(driver_graph):
        my_logger.debug("validation of root node")
        root_apis = factory.get_starting_api()
        if not node.api_call.original_api in root_apis:
            return None
    else:
        my_logger.debug("Validating non root node")

    try:
        new_ctx, unsat_vars = factory.try_to_instantiate_api_call(
            node.api_call,
            fcs.get_function_conditions(node.api_call.function_name),
            context,
        )
    except ConditionUnsat:
        my_logger.error(
            colored("can't satisfy function " + node.api_call.function_name, "red")
        )
        return None

    assert new_ctx is not None
    return new_ctx


def validate_driver(driver_graph: nx.DiGraph, config: Configuration) -> bool:
    """Validate an existing driver against Libfuzz static analysis

    Args:
        driver_graph (nx.DiGraph): CFG representation of the driver
        config (Configuration): Libfuzz configuration file

    Returns:
        bool: True if the driver can be generated according to Libfuzz static
              analysis
    """
    factory = config.factory
    if typing.assert_type(factory, CBFactory):
        cbfactory = cast(CBFactory, factory)
        running_context: RunningContext = RunningContext()
        for node in driver_graph:
            my_logger.debug("Validating node: " + node.api_call.function_name)
            rc = validate_node(
                node,
                running_context,
                driver_graph,
                cbfactory,
                config.function_conditions,
            )
            if rc is None:
                return False
            running_context = rc
            my_logger.debug("Node validated")
    return True


def driver_graph_init(config: Configuration) -> nx.DiGraph:
    """Dummy driver graph initilialization for testing

    Args:
        config (Configuration): LibTiff config

    Returns:
        nx.DiGraph: a dummy graph of 3 ApiCall chosen at random
    """
    api_list: List[Api] = list(config.api_list)
    assert len(api_list) > 0
    graph = nx.DiGraph()
    d_nodes = []
    root_dnode = None
    for api in api_list:
        a: ApiCall = config.factory.api_to_apicall(api)
        d_node = DriverNode(a)
        if api.function_name == "TIFFOpen":  # start function is fix
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

    driver_graph = driver_graph_init(config)
    if validate_driver(driver_graph, config):
        my_logger.debug(colored("Valid driver!", "green"))


if __name__ == "__main__":
    __main()
