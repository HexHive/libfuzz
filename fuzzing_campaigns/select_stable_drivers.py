#!/usr/bin/env python3

import csv, argparse, math
import numpy as np
import os


def sig(x):
    return 1/(1 + np.exp(-x))

def p2f(x):
    return float(x.strip('%'))/100

def calc_score(cov, n_crashes, n_unicrsh):
    return cov * sig(n_unicrsh) / sig(n_crashes)

def get_driver(raw_values):
    driver_id = raw_values[0]
    n_drivers = raw_values[1]
    n_apis = raw_values[2]
    # do not need this?
    # n_iter = raw_values[3]
    cov = p2f(raw_values[4])
    # no need
    # libcov = raw_values[5]
    n_crashes = int(raw_values[6])
    n_unicrsh = int(raw_values[7])

    score = calc_score(cov, n_crashes, n_unicrsh)

    return {"driver": driver_id,
            "n_drivers": n_drivers,
            "n_apis": n_apis,
            "cov": cov,
            "n_crashes": n_crashes,
            "n_unicrsh": n_unicrsh,
            "score": score}

def get_best_drivers(drvs):

    # keep only 10%
    perc_ok = math.ceil(len(drvs) * 0.10)

    # from IPython import embed; embed(); exit(1)

    return sorted(drvs, key=lambda x: x["score"], reverse=True)[:perc_ok]



def _main():

    parser = argparse.ArgumentParser(description='Select stable drivers')
    parser.add_argument('-report', '-r', type=str, help='Report File', required=True)

    args = parser.parse_args()

    report = args.report

    libraries = {}

    with open(report) as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',')

        next(spamreader)
        for row in spamreader:
            lib = row[0]
            drvs = libraries.get(lib, [])
            drvs += [get_driver(row[1:])]
            libraries[lib] = drvs


    best_drivers = {}

    # print(libraries)
    for lib, drvs in libraries.items():
        best_drvs = get_best_drivers(drvs)

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