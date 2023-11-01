#!/usr/bin/env python3

import csv, argparse, math
import numpy as np
import os, sys

PROJECT_FOLDER="../"
sys.path.append(PROJECT_FOLDER)

import tool.misc.score as scr

def _main():

    parser = argparse.ArgumentParser(description='Select stable drivers')
    parser.add_argument('-report', '-r', type=str, 
                        help='Report File', required=True)
    parser.add_argument('-rootdir', '-d', type=str, 
                        help='Driver Folder', required=False)
    parser.add_argument('-threshold', '-t', type=float, default=0.10,
                        help='Threshold for selection', required=False)
    parser.add_argument('-simulate', '-s', action='store_true',
                        help='Simulation only, not moving files around', 
                        required=False)

    args = parser.parse_args()

    report = args.report
    rootdir = args.rootdir
    simulate = args.simulate
    threshold = args.threshold

    libraries = scr.load_report(report, rootdir)

    best_drivers = {}

    # print(libraries)
    for lib, drvs in libraries.items():
        best_drvs = scr.get_best_drivers(drvs, threshold)

        best_drivers[lib] = best_drvs
        # print("-" * 10)
        # print(lib)
        # print(best_drvs)

    if simulate:
        print("[INFO] Only simulation, here the drivers I would select:")
        for lib, drvs in best_drivers.items():
            print(f"{lib}: {len(drvs)} drivers")
            for d in drvs:
                n_drivers = d['n_drivers']
                n_apis = d['n_apis']
                driver = d['driver']
                cov = d['cov']

                d_path = f"workdir_{n_drivers}_{n_apis}/{lib}/drivers/{driver}"
                print(f"{d_path}: {cov}")

            print("-" * 30)

        exit(0)
    
    print("exit anyway")
    exit(1)

    os.system("mkdir -p workdir_backup")
    os.system("mv workdir_*_*/ workdir_backup")

    # from IPython import embed; embed(); exit(1)

    for lib, drvs in best_drivers.items():
        print(f"{lib}: {len(drvs)} drivers")
        for d in drvs:
            n_drivers = d['n_drivers']
            n_apis = d['n_apis']
            driver = d['driver']

            # cp compiled driver
            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/drivers")
            os.system(f"cp {rootdir}/workdir_{n_drivers}_{n_apis}/{lib}/drivers/{driver} workdir_{n_drivers}_{n_apis}/{lib}/drivers")

            # cp source code driver
            os.system(f"cp {rootdir}/workdir_{n_drivers}_{n_apis}/{lib}/drivers/{driver}.cc workdir_{n_drivers}_{n_apis}/{lib}/drivers")

            # cp profile driver
            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/profiles")
            os.system(f"cp {rootdir}/workdir_{n_drivers}_{n_apis}/{lib}/profiles/{driver}_profile workdir_{n_drivers}_{n_apis}/{lib}/profiles")

            # cp corpus for driver
            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/corpus")
            os.system(f"cp -r {rootdir}/workdir_{n_drivers}_{n_apis}/{lib}/corpus/{driver} workdir_{n_drivers}_{n_apis}/{lib}/corpus")

            # os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/corpus_new")
            # os.system(f"cp -r workdir_{n_drivers}_{n_apis}/{lib}/corpus_new/{driver} workdir_{n_drivers}_{n_apis}/{lib}/corpus_new")

            os.system(f"mkdir -p workdir_{n_drivers}_{n_apis}/{lib}/crashes/{driver}")


if __name__ == "__main__":
    _main()