from functools    import cached_property

import os
from os import path
import json
from types import SimpleNamespace

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

    @cached_property
    def work_dir(self):
        wd = self._config["fuzzer"]["workdir"]
        tree = { "queue", "crash" }
        for t in tree:
            os.makedirs(os.path.join(wd, t), exist_ok=True)
        return wd

    @cached_property
    def dependency_generator(self):
        print("STUB: dependency_generator")
        return None

    @cached_property
    def driver_generator(self):
        print("STUB: driver_generator")
        return None