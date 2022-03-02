from functools    import cached_property

import os
from os import path
import json
from types import SimpleNamespace

from dependency import DependencyGraphGenerator, TypeDependencyGraphGenerator
from grammar import GrammarGenerator, NonTerminal
from driver import DriverGenerator
from miner import Miner, MockMiner, BackendDriver, MockBackendDriver

from fuzzer import Pool

class FuzzerConfig:
    """
    A parser for the JSON-formatted fuzzer configuration file.

    The file has the following structure:
    {
        "analysis": {
            "apis": "/path/to/apis.log",
            "coercemap": "/path/to/coercemap.txt",
            "headers": "/path/to/headers/*.h"
        },
        "fuzzer": {
            "workdir": "/path/to/workdir",
        }
    }
    """
    def __init__(self, config_path):
        
        if not path.isfile(config_path):
            raise(f"The configuration {config_path} is not valid")

        with open(config_path, "rt") as f:
            self._config = json.load(f)

        self.start_term = NonTerminal("start")

    @cached_property
    def work_dir(self):
        wd = self._config["fuzzer"]["workdir"]
        tree = { "queue", "crash" }
        for t in tree:
            os.makedirs(os.path.join(wd, t), exist_ok=True)
        return wd

    @cached_property
    def dependency_generator(self) -> DependencyGraphGenerator:

        if not "analysis" in self._config:
            raise Exception("'analysis' not defined")

        analysis = self._config["analysis"]

        if not "apis" in analysis:
            raise Exception("'apis' not defined")
        
        if not "headers" in analysis:
            raise Exception("'headers' not defined")

        if not "coercemap" in analysis:
            raise Exception("'coercemap' not defined")

        if not "dependency_policy" in analysis:
            raise Exception("'dependency_policy' not defined")

        api_logs = analysis["apis"]
        hedader_folder = analysis["headers"]
        coerce_map = analysis["coercemap"]
        dependency_policy = analysis["dependency_policy"]

        if dependency_policy == "only_type":
            return TypeDependencyGraphGenerator(api_logs, hedader_folder, coerce_map)

        raise NotImplementedError

    @cached_property
    def grammar_generator(self):
        return GrammarGenerator(self.start_term)

    @cached_property
    def driver_generator(self):

        if not "analysis" in self._config:
            raise Exception("'analysis' not defined")

        analysis = self._config["analysis"]

        if not "apis" in analysis:
            raise Exception("'apis' not defined")
        
        if not "headers" in analysis:
            raise Exception("'headers' not defined")

        if not "coercemap" in analysis:
            raise Exception("'coercemap' not defined")

        api_logs = analysis["apis"]
        hedader_folder = analysis["headers"]
        coerce_map = analysis["coercemap"]

        return DriverGenerator(api_logs, coerce_map, hedader_folder)

    @cached_property
    def miner(self) -> Miner:
        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        if not "miner" in fuzzer:
            raise Exception("'backend_driver' not defined")

        miner = fuzzer["miner"]
        
        if miner == "mock":
            return MockMiner(self.work_dir)

        raise NotImplementedError

    @cached_property
    def pool(self) -> Pool:
        # TODO: make pool_size in config

        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        if not "pool_size" in fuzzer:
            raise Exception("'pool_size' not defined")

        pool_size = fuzzer["pool_size"]

        return Pool(pool_size)