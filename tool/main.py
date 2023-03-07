#!/usr/bin/env python3

PROJECT_FOLDER="/workspaces/libfuzz"

import sys
sys.path.append(PROJECT_FOLDER)

import argparse
from framework import * 
from generator import Generator, Configuration
import logging

logging.getLogger().setLevel(logging.WARN)
logging.getLogger("generator").setLevel(logging.DEBUG)


def __main():

    # default_config = "./targets/simple_connection/generator.json"
    # default_config = PROJECT_FOLDER + "/regression_tests/condition_extractor/test_simpleapi/generator.toml"
    # default_config = PROJECT_FOLDER + "/regression_tests/condition_extractor/test_full/generator.toml"
    default_config = PROJECT_FOLDER + "/targets/libtiff/generator.toml"

    parser = argparse.ArgumentParser(description='Automatic Driver Generator')
    parser.add_argument('--config', type=str, help='The configuration', default=default_config)

    args = parser.parse_args()

    config = Configuration(args.config)
    sess = Generator(config)
    sess.run()

if __name__ == "__main__":
    __main()

