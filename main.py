#!/usr/bin/env python3

import argparse
from framework import * 
from generator import Generator, Configuration
import logging

logging.getLogger().setLevel(logging.WARN)
logging.getLogger("generator").setLevel(logging.DEBUG)


def __main():

    # default_config = "./targets/simple_connection/fuzz.json"
    default_config = "./targets/libtiff/generator.json"

    parser = argparse.ArgumentParser(description='Automatic Driver Generator')
    parser.add_argument('--config', type=str, help='The configuration', default=default_config)

    args = parser.parse_args()

    config = Configuration(args.config)
    sess = Generator(config)
    sess.run()

if __name__ == "__main__":
    __main()

