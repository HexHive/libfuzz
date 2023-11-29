#!/usr/bin/python3

import argparse, csv

PROJECT_FOLDER="/workspaces/libfuzz"

import sys, os
sys.path.append(PROJECT_FOLDER)
from framework import * 
from generator import Configuration
from constraints import ConditionManager
import copy

def get_utopia_data(utopia_folder):

    ..

    for f, p_b in uar["Array"].items():
        f_clean = f.split("(")[0]
        # print(f_clean)
        if f_clean in api_strings and "[" not in f and p_b != -1:
            # print(f"{f_clean} is found!!")

            x1 = f.find("(")
            x2 = f.find(")")
            p_a = f[x1+1:x2]
            
            real_utipia_api[f_clean] = (int(p_a), p_b)

def get_targets_data(targets):

    targets_data = {}    

    for t in os.listdir(targets):
        ft = os.path.join(targets, t)
        config_path = os.path.join(targets, t, "generator.toml")
        if os.path.isdir(ft) and os.path.isfile(config_path):
            try:
                config = Configuration(config_path)
                config.build_data_layout()
                config.build_condition_manager()

                targets_data[t] = copy.deepcopy(ConditionManager.instance())
            except:
                pass

    return targets_data
            
def parse_gt(groundtruth):

    gt = {}
    
    with open(groundtruth) as f:
        gt_csv = csv.DictReader(f, delimiter=',', quotechar='"')
        for l in gt_csv:
            library = l["Library"]
            function, pos  = l["API function:argument (-1 return)"].split(":")

            arg_info = {}
            arg_info["malloc_size"] = l["malloc size"] == "TRUE"
            arg_info["file_path"] = l["file path"] == "TRUE"
            arg_info["buffer"] = l["buffer (var len)"] == "TRUE"
            arg_info["length"] = l["length (var len)"]
            arg_info["create"] = l["create"] == "TRUE"
            arg_info["static"] = l["static"] == "TRUE"
            arg_info["source"] = l["source"] == "TRUE"
            arg_info["sink"] = l["sink"] == "TRUE"
            arg_info["init"] = l["init api"] == "TRUE"

            l_info = gt.get(library, {})
            f_info = l_info.get(function, {})
            f_info[pos] = arg_info
            l_info[function] = f_info
            gt[library] = l_info

    return gt

def _main():
    parser = argparse.ArgumentParser(description='Counts the API used')
    parser.add_argument('-groundtruth', '-g', type=str, help='Ground Trurth CSV File (ask the authors)', required=True)
    parser.add_argument('-targets', '-t', type=str, help='Folder with target libraries', required=True)
    parser.add_argument('-utopia', '-u', type=str, help='Folder with Utopia resultstarget', required=True)

    args = parser.parse_args()

    groundtruth = args.groundtruth
    targets = args.targets
    utopia = args.utopia
    
    gt_data = parse_gt(groundtruth)
    targets_data = get_targets_data(targets)

    from IPython import embed; embed(); exit(1)
    

if __name__ == "__main__":
    _main()