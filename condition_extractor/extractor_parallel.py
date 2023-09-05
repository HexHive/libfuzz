#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import multiprocessing as mp
import argparse
from enum import Enum
import json

class Extractor(object):

    def __init__(self, target, minimize_api, v, t, do_indirect_jumps, data_layout):
        self.dir_path = os.path.dirname(os.path.realpath(__file__))
        self.target = target
        self.minimize_api = minimize_api
        self.v = v
        self.t = t
        self.do_indirect_jumps = do_indirect_jumps
        self.data_layout = data_layout


    def run(self, functions_file):
        subprocess.run([os.path.join(self.dir_path, "bin/extractor"), 
                        self.target, 
                        "-interface",
                        os.path.splitext(functions_file)[0] + "_cond" + '.json', 
                        "-minimize_api", self.minimize_api, 
                        "-v", str(self.v), "-t", str(self.t), 
                        "-do_indirect_jumps" if self.do_indirect_jumps else "", 
                        "-data_layout", self.data_layout, 
                        '-diff'])

class VerbosityLevel(Enum):
    v0 = "v0"
    v1 = "v1"
    v2 = "v2"
    v3 = "v3"

    def __str__(self):
        return self.value


class OutputType(Enum):
    json = 'json'
    txt = 'txt'
    stdo = 'stdo'

    def __str__(self):
        return self.value


def __main():

    parser = argparse.ArgumentParser(description='Run extractor in parallel')
    parser.add_argument('target', type=str, help='The target bitcode')
    parser.add_argument('-interface', type=str, help='The configuration', required=True)

    parser.add_argument('-output', type=str, help='The output file', required=True)
    parser.add_argument('-minimize_api', type=str, help='The minimized api', required=True)
    parser.add_argument('-v', type=VerbosityLevel, help='The verbosity', choices=list(VerbosityLevel), default=VerbosityLevel.v0)
    parser.add_argument('-t', type=OutputType, help='The output type', choices=list(OutputType), default=OutputType.stdo)
    parser.add_argument('-do_indirect_jumps', help='Do indirect jumps', action='store_true')
    parser.add_argument('-data_layout', type=str, help='The data layout', required=True)


    args = parser.parse_args()
    CHUNK_SIZE = 20
    functions_files = []
    with open(args.interface, 'r') as interface:
        functions = interface.readlines()
        for idx, i in enumerate(range(0, len(functions), CHUNK_SIZE)):
            with open(os.path.splitext(args.interface)[0] + "_" + str(i) + '.json', 'w') as out:
                out.writelines(functions[idx:idx+CHUNK_SIZE])
                functions_files.append(out.name)

    extractor = Extractor(args.target, args.minimize_api, args.v, args.t, args.do_indirect_jumps, args.data_layout)
    pool = mp.Pool()                         # Create a multiprocessing Pool
    pool.map(extractor.run, functions_files)

    global_res = []
    for f in functions_files:
        with open(os.path.splitext(f)[0] + "_cond" + '.json', "r") as json_file:
            global_res.append(json.loads(json_file))

    with open(args.output, 'w') as out:
        json.dump(global_res, out)

if __name__ == "__main__":
    __main()
