#!/usr/bin/env python3

import csv, argparse, math

import score as scr

def get_best_drivers(drvs):


    # keep only 10%
    perc_ok = math.ceil(len(drvs) * 0.10)
    # return sorted(drvs, key=lambda x: x["score"], reverse=True)[:perc_ok]

    best_driver = []

    max_api = set()
    for d in sorted(drvs, key=lambda x: x["score"], reverse=True):
        api_set = set(d["metadata"]["api_multiset"].keys())
        print(f"api set: {api_set}")
        if len(max_api) == 0:
            max_api = api_set
            best_driver += [d]
            print("first set")
        elif not api_set.issubset(max_api):
            max_api = max_api.union(api_set)
            best_driver += [d]
            print(f"new max_api: {max_api}")
        else:
            print("skip!")
        
        if len(best_driver) >= perc_ok:
            break

    return best_driver

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
        best_drvs = get_best_drivers(drvs)

        best_drivers[lib] = best_drvs

    # FROM HERE    
    for lib, drvs in best_drivers.items():
        print(f"{lib}")
        for d in drvs:
            print(d)
        

if __name__ == "__main__":
    _main()