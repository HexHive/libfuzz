#!/usr/bin/env python3

import csv, argparse, math
import numpy as np
import os, sys

PROJECT_FOLDER="/workspaces/libfuzz"
sys.path.append(PROJECT_FOLDER)

import tool.misc.score as scr

def _main():

    parser = argparse.ArgumentParser(description='Select stable drivers')
    parser.add_argument('-report', '-r', type=str, help='Report File', required=True)
    parser.add_argument('-rootdir', '-d', type=str, help='Driver Folder', required=False)

    args = parser.parse_args()

    report = args.report
    rootdir = args.rootdir

    libraries = scr.load_report(report, rootdir)

    best_drivers = {}

    # print(libraries)
    for lib, drvs in libraries.items():
        best_drvs = scr.get_best_drivers(drvs)

        best_drivers[lib] = best_drvs

    # FROM HERE
    for lib, drvs in best_drivers.items():
        print(f"{lib}")
        for d in drvs:
            n_drivers = d['n_drivers']
            n_apis = d['n_apis']
            driver = d['driver']


            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/drivers")
            os.system(f"cp workdir_backup/workdir_{n_drivers}_{n_apis}/{lib}/drivers/{driver} workdir_{n_drivers}_{n_apis}/{lib}/drivers")
            os.system(f"cp workdir_backup/workdir_{n_drivers}_{n_apis}/{lib}/drivers/{driver}.cc workdir_{n_drivers}_{n_apis}/{lib}/drivers")

            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/profiles")
            os.system(f"cp workdir_backup/workdir_{n_drivers}_{n_apis}/{lib}/profiles/{driver}_profile workdir_{n_drivers}_{n_apis}/{lib}/profiles")

            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/corpus")
            os.system(f"cp -r workdir_backup/workdir_{n_drivers}_{n_apis}/{lib}/corpus/{driver} workdir_{n_drivers}_{n_apis}/{lib}/corpus")

            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/corpus_new")
            os.system(f"cp -r workdir_backup/workdir_{n_drivers}_{n_apis}/{lib}/corpus_new/{driver} workdir_{n_drivers}_{n_apis}/{lib}/corpus_new")

            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/crashes/{driver}")


if __name__ == "__main__":
    _main()