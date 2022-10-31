from functools    import cached_property

import os
from os import path
import json
from types import SimpleNamespace

from dependency import DependencyGraphGenerator, TypeDependencyGraphGenerator
from grammar import GrammarGenerator, NonTerminal, Terminal
from driver import DriverGenerator
from backend import BackendDriver, MockBackendDriver, LFBackendDriver
from common import Utils

from fuzzer import Pool, FuzzerWrapper

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
        self.end_term = Terminal("end")

    @cached_property
    def driver_size(self):

        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        # default value
        if not "driver_size" in fuzzer:
            return 10

        return fuzzer["driver_size"]

    @cached_property
    def fuzzer_wrapper(self):

        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        # default value
        if not "docker_path" in fuzzer:
            raise Exception("'docker_path' not defined")
        docker_path = fuzzer["docker_path"]

        # default value
        if not "context_path" in fuzzer:
            raise Exception("'context_path' not defined")
        context_path = fuzzer["context_path"]

        # default value
        if not "fuzzer_verbose" in fuzzer:
            fuzzer_verbose = False
        else:
            fuzzer_verbose = fuzzer["fuzzer_verbose"]

        return FuzzerWrapper(docker_path, context_path, fuzzer_verbose)

    @cached_property
    def work_dir(self):
        wd = self._config["fuzzer"]["workdir"]
        os.makedirs(wd, exist_ok=True)
        return wd

    @cached_property
    def queue_dir(self):
        d = os.path.join(self.work_dir, "queue")
        os.makedirs(d, exist_ok=True)
        return d

    @cached_property
    def target_library(self):
        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        # default value
        if not "target_library" in fuzzer:
            raise Exception("'target_library' not defined")

        return fuzzer["target_library"]

    @cached_property
    def fuzzer_timeout(self):
        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        # default value
        if not "fuzzer_timeout" in fuzzer:
            raise Exception("'fuzzer_timeout' not defined")

        return fuzzer["fuzzer_timeout"]

    @cached_property
    def fuzzer_nane(self):
        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        # default value
        if not "fuzzer_nane" in fuzzer:
            raise Exception("'fuzzer_nane' not defined")

        return fuzzer["fuzzer_nane"]

    @cached_property
    def cache_dir(self):
        d = os.path.join(self.work_dir, "cache")
        os.makedirs(d, exist_ok=True)
        return d

    @cached_property
    def drivers_dir(self):
        d = os.path.join(self.work_dir, "drivers")
        os.makedirs(d, exist_ok=True)
        return d

    @cached_property
    def seeds_dir(self):
        d = os.path.join(self.work_dir, "corpus")
        os.makedirs(d, exist_ok=True)
        return d
    

    @cached_property
    def headers_dir(self):
        if not "backend" in self._config:
            raise Exception("'backend' not defined")

        backend = self._config["backend"]

        if not "headers" in backend:
            raise Exception("'headers' not defined")

        return backend["headers"]

    @cached_property
    def reports_dir(self):
        d = os.path.join(self.work_dir, "reports")
        os.makedirs(d, exist_ok=True)
        return d

    @cached_property
    def dependency_generator(self) -> DependencyGraphGenerator:

        if not "analysis" in self._config:
            raise Exception("'analysis' not defined")

        analysis = self._config["analysis"]

        # if not "apis" in analysis:
        #     raise Exception("'apis' not defined")
        
        # if not "headers" in analysis:
        #     raise Exception("'headers' not defined")

        # if not "coercemap" in analysis:
        #     raise Exception("'coercemap' not defined")

        if not "dependency_policy" in analysis:
            raise Exception("'dependency_policy' not defined")

        # api_logs = analysis["apis"]
        # hedader_folder = analysis["headers"]
        # coerce_map = analysis["coercemap"]
        dependency_policy = analysis["dependency_policy"]

        if dependency_policy == "only_type":
            return TypeDependencyGraphGenerator(self.api_list)

        raise NotImplementedError
    @cached_property
    def grammar_generator(self):
        return GrammarGenerator(self.start_term, self.end_term)

    @cached_property
    def api_list(self):

        if not "analysis" in self._config:
            raise Exception("'analysis' not defined")

        analysis = self._config["analysis"]

        if not "apis_llvm" in analysis:
            raise Exception("'apis_llvm' not defined")

        if not "apis_clang" in analysis:
            raise Exception("'apis_clang' not defined")
        
        if not "headers" in analysis:
            raise Exception("'headers' not defined")

        if not "coercemap" in analysis:
            raise Exception("'coercemap' not defined")

        apis_llvm = analysis["apis_llvm"]
        apis_clang = analysis["apis_clang"]
        hedader_folder = analysis["headers"]
        coerce_map = analysis["coercemap"]
        incomplete_types = analysis["incomplete_types"]

        # t = Utils.get_api_list(apis_llvm, apis_clang, coerce_map, hedader_folder, incomplete_types)
        # from IPython import embed; embed(); exit()
        return Utils.get_api_list(apis_llvm, apis_clang, coerce_map, hedader_folder, incomplete_types)

    @cached_property
    def driver_generator(self):
        return DriverGenerator(self.api_list, self.driver_size)
        
    @cached_property
    def num_seeds(self):
        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        if not "num_seeds" in fuzzer:
            raise Exception("'num_seeds' not defined")

        return int(fuzzer["num_seeds"])

    @cached_property
    def backend(self) -> BackendDriver:
        if not "fuzzer" in self._config:
            raise Exception("'fuzzer' not defined")

        fuzzer = self._config["fuzzer"]

        if not "backend" in fuzzer:
            raise Exception("'backend_driver' not defined")

        backend = fuzzer["backend"]
        
        if backend == "mock":
            return MockBackendDriver(self.drivers_dir, self.seeds_dir, self.num_seeds)

        if backend == "libfuzz":
            return LFBackendDriver(self.drivers_dir, self.seeds_dir, self.num_seeds, self.headers_dir)

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