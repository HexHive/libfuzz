#!/usr/bin/env python3

import os, json, argparse

def _main():

    parser = argparse.ArgumentParser(description='Counts the API used')
    parser.add_argument('-root', '-r', type=str, help='Report File', required=True, default="/media/hdd0/libfuzz_scratchpad/main/fuzzing_campaigns")
    
    args = parser.parse_args()
    
    d = args.root
    # libs =  "cpu_features libtiff minijail pthreadpool libaom libvpx libhtp libpcap c-ares zlib cjson".split()
    # libs =  "cjson".split()
    libs = set()

    workdir_token = "workdir_"

    # n_drivers = 40
    # apis = [2, 4, 8, 16, 32]    
    apis = []
    n_drivers = set()

    workdirs = set()
    for x in os.listdir(d):
        if x.startswith(workdir_token):
            workdirs.add(os.path.join(d, x))
            n_driver, n_api = x.replace(workdir_token, "").split("_")
            apis += [int(n_api)]
            n_drivers = int(n_driver)
    
    for w in workdirs:
        for l in os.listdir(w):
            libs.add(l)
    
    base_fold = f"{workdir_token}{n_drivers}_"
    
    stats = {}
    for a in apis:
        for l in libs:
            ll = stats.get(l, set())
            stats[l] = ll
            for i in range(n_drivers):
                fp = os.path.join(d, f"{base_fold}{a}", l, "metadata", f"driver{i}.meta")
                with open(fp, "r") as f:
                    md = json.load(f)
                am = md["api_multiset"]
                for au in am.keys():
                    stats[l].add(au)
    for l, s in stats.items():
        print(f"{l}: {len(s)}")

if __name__ == "__main__":
    _main()