#!/usr/bin/env python3

import os, json, argparse
import matplotlib.pyplot as plt

tot_api = {
    "pthreadpool": 30,
    "libaom": 47,
    "zlib": 88,
    "c-ares": 126,
    "cpu_features": 7,
    "libpcap": 88,
    "cjson": 78,
    "libvpx": 35,
    'libtiff': 197,
    "minijail": 97,
    "libhtp": 251
}

def read_drivers_metadata(d):
    
    driver_meta = {}
    
    for l in os.listdir(os.path.join(d, "metadata")):
        if l.endswith(".meta"):
            with open(os.path.join(d, "metadata", l), "r") as f:
                md = json.load(f)
            driver_meta[l.replace(".meta", "")] = md
            
    return driver_meta

def read_paths_observed(d):
    
    paths_observed = []
    
    with open(os.path.join(d, "paths_observed.txt")) as f:
        for l in f:
            if l:
                la = l.split(":")
                driver = la[0]
                apis = set(la[1].split(";"))
                status = la[2]
                n_seeds = int(la[3])
                
                paths_observed += [{"driver": driver,
                                    "apis": apis, 
                                    "status": status, 
                                    "n_seed": n_seeds}]
        
    return paths_observed                
                

def _main():
    
    parser = argparse.ArgumentParser(description='APIs used over time')
    parser.add_argument('-root', '-r', type=str, help='Root folder', required=True, default="/media/hdd0/libfuzz_scratchpad/main/fuzzing_campaigns")
    parser.add_argument('-p', action='store_true', help='Only positive')
    
    args = parser.parse_args()
    
    root_folder = args.root
    
    print(root_folder)
    
    # drivers_metadata = read_drivers_metadata(root_folder)
    
    for t, max in tot_api.items():
        
        root_folder_p = os.path.join(root_folder, t, "iter_1")
        
        paths_observed = read_paths_observed(root_folder_p)
        
        # print(paths_observed)
        # exit(1)
        
        # from IPython import embed; embed(); exit(1)
        
        n_api_acc = set()
        
        max_api = tot_api[t]
        
        x = []
        y = []    
        for i, d in enumerate(paths_observed):
            n_api_acc |= d["apis"]
            # print(len(n_api_acc))
            x += [i]
            y += [len(n_api_acc)]
            
        plt.cla()
        
        plt.plot(x, y, label='APIs used over time')    
        
        plt.title('Simple Line Plot')
        plt.xlabel('x')
        plt.ylabel('y')
        
        plt.legend()
        
        plt.savefig(f"api_over_time_{t}.pdf", format='pdf')
        
    
if __name__ == "__main__":
    _main()