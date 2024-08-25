#!/usr/bin/env python3


import argparse, os
import numpy as np
import matplotlib.pyplot as plt

def get_runs(rootdir, is_grammar):
    
    if is_grammar:
        return len(os.listdir(rootdir))
    
    raise Exception("get_runs w/o is_grammar not implemented yet")
    

def _main():
    parser = argparse.ArgumentParser(description='Print comulative coverage')
    parser.add_argument('-working_dir', '-d', type=str, help='Work Dir', required=True)
    parser.add_argument('-target', '-t', type=str, help='Target Name', required=True)
    parser.add_argument('-is_grammar', '-g', action='store_true', 
                        help='Comes from grammar mode?', required=False)
                    

    args = parser.parse_args()
    
    workdir = args.working_dir
    target = args.target
    is_grammar = args.is_grammar
    
    rootdir = os.path.join(workdir, target)
    
    n_runs = get_runs(rootdir, is_grammar)
    
    data = []
    
    for i in range(1, n_runs+1):
        if is_grammar:
            cov_dir = os.path.join(rootdir, f"iter_{i}", "coverage_data")
        else:
            raise Exception("I can't handle w/o is_grammar")
            
        raw_data = dict()
        
        for a_driver in os.listdir(cov_dir):
            # Get the full path of the item
            f_path = os.path.join(cov_dir, a_driver)
            
            # Check if it is a directory and if it starts with "driver"
            if os.path.isdir(f_path) and a_driver.startswith("driver"):
                with open(os.path.join(f_path, "report_comulative"), "r") as f:
                    # report_comulative should have only one line
                    line = f.readline()
                    cov = line.split()[-1].replace("%", "")
                    
                raw_data[a_driver] = float(cov)

        # from IPython import embed; embed(); exit(1)
        data += [list(raw_data[key] for key in sorted(raw_data.keys(), key=lambda k: int(k[6:])))]
        # print(data)
                

    max_len = max(len(cov) for cov in data)

    # I propagate last element if series' length does not match
    for cov in data:
        to_add = max_len - len(cov) 
        last_el = cov[-1]
        for _ in range(to_add):
            cov += [last_el]

    # from IPython import embed; embed(); exit(1)

    # Add title and labels
    plt.title('Comulative Coverage')
    plt.xlabel('N. Drivers')
    plt.ylabel('Com. Coverage')

    # Calculate the mean, max, and min across the temporal series (axis=0 for column-wise operation)
    mean_series = np.mean(data, axis=0)
    max_series = np.max(data, axis=0)
    min_series = np.min(data, axis=0)


    # from IPython import embed; embed(); exit(1)

    # Plotting
    plt.figure(figsize=(10, 6))
    plt.plot(mean_series, label='Average', color='blue')
    plt.plot(max_series, label='Max', color='red')
    plt.plot(min_series, label='Min', color='green')

    # Optional: Fill between min and max for visualization
    plt.fill_between(range(max_len), min_series, max_series, color='gray', alpha=0.2)

    # Add a legend
    plt.legend()

    # Display the plot
    plt.savefig(f"{target}_comulative.pdf")
    
    
if __name__ == "__main__":
    _main()