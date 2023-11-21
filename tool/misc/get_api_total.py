#!/usr/bin/env python3

PROJECT_FOLDER="/workspaces/libfuzz"

import sys, os
sys.path.append(PROJECT_FOLDER)

import argparse
from framework import * 
from generator import Configuration
import logging


def __main():
    
    parser = argparse.ArgumentParser(description='Get all APIs for each library')
    parser.add_argument('--targets', '-t', type=str, help='Targets folder', required=True)

    args = parser.parse_args()

    targets = args.targets

    libs = set()

    api_per_lib = set()

    for t in os.listdir(targets):
        ft = os.path.join(targets, t)
        config_path = os.path.join(targets, t, "generator.toml")
        if os.path.isdir(ft) and os.path.isfile(config_path):
            try:
                config = Configuration(config_path)
                api_list_all = config.api_list_all
                api_per_lib.add((t, len(api_list_all)))
            except:
                pass

    for x in list(api_per_lib):
        l, a = x[0], x[1]
        print(f"{l},{a}")

if __name__ == "__main__":
    __main()
