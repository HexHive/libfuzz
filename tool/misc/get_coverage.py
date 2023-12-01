#!/usr/bin/python3

import os, argparse, subprocess

def is_ok(line, allowed_files):
    
    record = line.split()

    if not record:
        return False
    
    file = record[0]

    if "/" in file:
        file = file.split("/")[-1]

    return file in allowed_files
        # print("is_ok")
        # from IPython import embed; embed()


def _main():
    parser = argparse.ArgumentParser(description='Calculate Coverage from Utopia reports')
    parser.add_argument('-reports', '-r', type=str, help='Report Files', required=True)
    parser.add_argument('-groundtruth', '-g', type=str, help='Ground Truth', required=True)
    parser.add_argument('-max', '-m', type=int, help='Number of Runs', required=True)
    
    args = parser.parse_args()

    reports = args.reports
    groundtruth = args.groundtruth
    max_run = args.max

    ground_truth_files = {}
    for l in os.listdir(groundtruth):
        ground_truth_files[l] = set()

    begin = "-"
    end = "Files which"

    for p in ground_truth_files.keys():
        filename = os.path.join(groundtruth, p, "iter_1", "report")
        with open(filename) as f:
            start_reading = False
            for l in f:
                if l.strip() == "":
                    continue
                if l.startswith(begin):
                    start_reading = True
                    continue
                if start_reading:
                    the_file = l.split()[0]
                    if l.startswith(end):
                        start_reading = False 
                        break
                    if "/" in the_file:
                        the_file = the_file.split("/")[-1]
                    ground_truth_files[p].add(the_file)


    # from IPython import embed; embed(); exit(1)

    projects = set()

    for l in os.listdir(reports):
        projects.add(l)

    print("library,run,lines,branches")
        
    for p in projects:
        for i in range(1, max_run+1):
            filename = os.path.join(reports, p, f"iter_{i}", "report")
            # print(filename)
            branch = 0
            miss_branch = 0
            line = 0
            miss_line = 0
            with open(filename) as f:
                for l in f:
                    if is_ok(l, ground_truth_files[p]):
                        l_arr = l.split()
                        branch += int(l_arr[10])
                        miss_branch += int(l_arr[11])
                        line +=  int(l_arr[7])
                        miss_line += int(l_arr[8])

            branches = branch-miss_branch
            lines = line-miss_line
            print(f"{p},{i},{lines},{branches}")
        

if __name__ == "__main__":
    _main()
