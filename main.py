#!/usr/bin/env python3

import argparse
from framework import *
from fuzzer import FuzzerSession, FuzzerConfig
import logging

logging.getLogger().setLevel(logging.WARN)
logging.getLogger("statemanager").setLevel(logging.DEBUG)
logging.getLogger("networkio").setLevel(logging.INFO)
logging.getLogger("fuzzer").setLevel(logging.DEBUG)


def __main():

    # default_config = "./targets/simple_connection/fuzz.json"
    default_config = "./targets/libtiff/fuzz.json"

    parser = argparse.ArgumentParser(description='Automatic Driver Generator')
    parser.add_argument('--config', type=str, help='The grammar', default=default_config)

    args = parser.parse_args()

    config = args.config

    config = FuzzerConfig(config)
    sess = FuzzerSession(config)
    sess.run()

if __name__ == "__main__":
    __main()

