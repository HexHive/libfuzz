#!/usr/bin/env python3

import os, json, argparse
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
plt.rcParams['text.usetex'] = True
tot_api = {
    "c-ares": 126,
    "cjson": 78,
    "cpu_features": 7,
    "libaom": 47,
    "libhtp": 251,
    "libpcap": 88,
    'libtiff': 197,
    "libvpx": 35,
    "minijail": 97,
    "pthreadpool": 30,
    "zlib": 88,
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
   
    f = plt.figure(figsize=(24, 8))
    gs = gridspec.GridSpec(8, 24)
    ax =[0]*12
    for i in range(0,11):
        if i//6 == 0:
            ax[i] = f.add_subplot(gs[0:4, 0+i*4:4+i*4])
        else:
            ax[i] = f.add_subplot(gs[4:8, 2+(i-6)*4:6+(i-6)*4])
    f.set_tight_layout(True)
    plot_index = 0
    for t, max in tot_api.items():
        print(t)
        iterations = 5
        x = [0] * iterations
        y = [0] * iterations
        for iter in range(0, iterations): 
            root_folder_p = os.path.join(root_folder, t, "iter_" + str(iter+1))
        
            paths_observed = read_paths_observed(root_folder_p)
        
            # print(paths_observed)
            # exit(1)
        
            # from IPython import embed; embed(); exit(1)
        
            n_api_acc = set()
        
            x[iter] = []
            y[iter] = []    
            for i, d in enumerate(paths_observed):
                n_api_acc |= d["apis"]
                # print(len(n_api_acc))
                x[iter] += [i]
                y[iter] += [len(n_api_acc)]
            
        stop = False
        new_max = 0
        newx = []
        idx = 0
        for i in range(0, iterations):
            if len(x[i]) > new_max:
                new_max = len(x[i])
                newx = x[i]
        newy = [0]*new_max
        last = [0]*iterations
        while not stop:
            stop = True
            for i in range(0, iterations):
                if idx < len(x[i]):
                    last[i] =  y[i][idx]
            
                    stop = False
            if not stop:
                newy[idx] = sum(last)/iterations/max*100
            idx += 1
        plt.cla()

        plt.plot(newx, newy, label='APIs used over time')    

        plt.title("\\texttt{" + t+ "}")
        plt.xlabel('\# of drivers')
        plt.ylabel('Percentage of API functions reached')
        plt.ylim(top=105)

        plt.savefig(f"api_over_time_{t}.pdf", format='pdf')

        ax[plot_index].plot(newx, newy, label='APIs used over time')    
        ax[plot_index].set_title("\\texttt{" + t+ "}")
        ax[plot_index].set_xlabel('\# of drivers')
        ax[plot_index].set_ylabel('Percentage of API functions reached')
        ax[plot_index].set_ylim(bottom=0, top=105)
        #ax[plot_index].set_lim(xmin=0)
        #ax[pp].legend()



        plot_index += 1
    #f.suptitle('This is a somewhat long figure title', fontsize=16)
    plt.savefig(f"api_over_time.pdf", format='pdf')
        
    
if __name__ == "__main__":
    _main()
