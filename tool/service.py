#!/usr/bin/env python3

PROJECT_FOLDER="/workspaces/libfuzz"

from flask import Flask, request
import threading

import sys
sys.path.append(PROJECT_FOLDER)

app = Flask(__name__)

import argparse
from framework import * 
from generator import Generator, Configuration
import logging

# Shared counter variable
# not sure I need that
lock = threading.Lock()  # Lock to ensure thread safety
sess = None
drivers_list = dict()

@app.route('/')
def index():
    if sess is None:
        return "Session not loaded. Check configuration."
    else:
        config_info = sess._config.get_info()
        return f"Session loaded w/: {config_info}"

@app.route('/get_new_driver')
def get_new_driver():

    driver = sess._factory.create_random_driver()
    driver_name = sess._backend.get_name()

    print(f"Storing driver: {driver_name}") 
    sess._backend.emit_driver(driver, driver_name)

    print(f"Storing seeds for: {driver_name}")
    sess._backend.emit_seeds(driver, driver_name)

    print(f"Storing metadata for {driver_name}:")
    sess.dump_metadata(driver, driver_name)

    if driver_name.endswith(".cc"):
        driver_name = driver_name[:-3]

    drivers_list[driver_name] = driver

    return driver_name

@app.route('/push_feedback')
def push_feedback():
    driver = request.args.get('driver', '')
    if driver == '':
        return "Error: no driver name"
    
    time = request.args.get('time', -1)
    if time == -1:
        return "Error: time not given"

    cause = request.args.get('cause', '')
    if cause == -1:
        return "Error: cause not given"

    with open("/workspaces/libfuzz/feedback_received.txt", "a") as f:
        f.write(f"{driver}|{time}|{cause}\n")

    return "ok"

if __name__ == '__main__':

    # default_config = PROJECT_FOLDER + "/regression_tests/condition_extractor/test_simpleapi/generator.toml"
    # default_config = PROJECT_FOLDER + "/regression_tests/condition_extractor/test_full/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/uriparser/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/libhtp/generator.toml"
    default_config = PROJECT_FOLDER + "/targets/libtiff/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/cpu_features/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/minijail/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/libvpx/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/pthreadpool/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/libaom/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/libpcap/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/c-ares/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/cjson/generator.toml"
    # default_config = PROJECT_FOLDER + "/targets/zlib/generator.toml"

    parser = argparse.ArgumentParser(description='Automatic Driver Generator')
    parser.add_argument('--config', type=str, help='The configuration', default=default_config)

    parser.add_argument('--overwrite', type=str, help='Set of parameters that overwrite the `config` toml file. Used to standardize configuration when testing multipe libraries.')

    args = parser.parse_args()

    config = Configuration(args.config, args.overwrite)

    sess = Generator(config)

    app.run(debug=True)
