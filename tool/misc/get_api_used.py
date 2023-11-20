#!/usr/bin/env python3

import os, json, argparse

def _main():

    parser = argparse.ArgumentParser(description='Counts the API used')
    parser.add_argument('-root', '-r', type=str, help='Report File', required=True, default="/media/hdd0/libfuzz_scratchpad/main/fuzzing_campaigns")
    parser.add_argument('-camp_conf', '-c', type=str, help='Campaing configuration', required=True)

    args = parser.parse_args()
    
    d = args.root

    libs = ['c-ares', 'cjson', 'cpu_features', 'libaom', 'libhtp', 'libpcap', 'libtiff', 'libvpx', 'minijail', 'pthreadpool', 'zlib']

    base_fold = "workdir_40_"
        
    stats = {}
    for a in apis:
        for l in libs:
            ll = stats.get(l, set())
            stats[l] = ll
            for i in range(50):
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