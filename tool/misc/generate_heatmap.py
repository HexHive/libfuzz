#!/usr/bin/env python3

import matplotlib.pyplot as plt
import numpy as np
from os import listdir
import argparse

def get_function_coverages(coverage_file):
    result = {}

    with open(coverage_file) as fcoverage:
        for line in fcoverage:
            line = line.strip()
            if not line:
                continue
            if line.startswith("-"):
                continue
            if line.startswith("Name"):
                continue
            if line.startswith("File "):
                continue
            line = line.split()
            function_name = line[0]
            coverage = float(line[3].rstrip("%"))
            result[function_name] = coverage
    return result

def get_coverage_files_for_drivers(project, list_of_drivers):
    result = {}
    for ndrivers, napis, driver_name in list_of_drivers:
        result[f"{ndrivers}_{napis}_{driver_name}"] = f"./workdir_{ndrivers}_{napis}/{project}/coverage_data/{driver_name}/functions"
    return result

def get_coverage_files_for_configuration(project, napis, ndrivers):
    result = {}
    project_folder = f"./workdir_{napis}_{ndrivers}/{project}"
    drivers = [driver[:-3] for driver in listdir(f"{project_folder}/drivers") if driver.endswith(".cc")]

    for driver in drivers:
        result[driver] = f"{project_folder}/coverage_data/{driver}/functions"
    result["total"] = f"{project_folder}/coverage_data/total/functions"
    return result

def get_coverage_datas_for_drivers(project, list_of_drivers):
    coverage_files = get_coverage_files_for_drivers(project, list_of_drivers)
    coverage_datas = {}
    functions = []

    for name in sorted(coverage_files.keys()):
        coverage_file = coverage_files[name]
        coverages = get_function_coverages(coverage_file)

        functions.append(list(coverages.keys()))

    functions = list(set.intersection(*map(set, functions)))

    for name in sorted(coverage_files.keys()):
        coverage_file = coverage_files[name]
        coverages = get_function_coverages(coverage_file)
        coverage_list = []
        for function in functions:
            coverage_list.append(coverages[function])
        coverage_datas[name] = np.array(coverage_list)

    return coverage_datas

def get_coverage_datas_for_configuration(project, ndrivers, napis):
    coverage_files = get_coverage_files_for_configuration(project, ndrivers, napis)
    coverage_datas = {}
    function_hit_or_not = {}
    functions = []

    for name in sorted(coverage_files.keys()):
        coverage_file = coverage_files[name]
        coverages = get_function_coverages(coverage_file)

        functions.append(list(coverages.keys()))

    functions = list(set.intersection(*map(set, functions)))

    for name in sorted(coverage_files.keys()):
        coverage_file = coverage_files[name]
        coverages = get_function_coverages(coverage_file)

        coverage_list = []

        for function in functions:
            coverage_list.append(coverages[function])
            if coverages[function] > 0:
                function_hit_or_not[function] = 100
            else:
                if function not in function_hit_or_not:
                    function_hit_or_not[function] = 0
        coverage_datas[name] = np.array(coverage_list)

    hit_or_not = []
    for function in functions:
        hit_or_not.append(function_hit_or_not[function])
    coverage_datas["hit"] = np.array(hit_or_not)
    return coverage_datas


def draw_figure(project, coverage_datas):
    # Set up the figure and axes with a smaller figsize
    fig, axes_tuple = plt.subplots(nrows=len(coverage_datas), figsize=(3, 0.5))

    # Create a colormap
    cmap = plt.cm.RdYlGn

    # Normalize coverage percentages to the range [0, 1]
    norm = plt.Normalize(0, 100)

    idx = 0
    for name in sorted(coverage_datas.keys()):
        coverage_data = coverage_datas[name]
        normalized_coverage = norm(coverage_data)
        x = np.arange(len(coverage_data))
        bar_height = 1
        axes_tuple[idx].bar(x, height=bar_height, width=1, color=cmap(normalized_coverage), edgecolor='none', )
        axes_tuple[idx].xaxis.set_visible(False)
        axes_tuple[idx].set_ylabel(name, fontsize=2, rotation=0)
        plt.setp(axes_tuple[idx].get_xticklabels(), visible=False)
        plt.setp(axes_tuple[idx].get_yticklabels(), visible=False)
        axes_tuple[idx].tick_params(axis='both', which='both', length=0)
        idx += 1

    axes_tuple[0].set_title(f"{project} Coverage Heatmap")
    plt.subplots_adjust(hspace=0)
    plt.savefig(f'{project}_heatmap.png', dpi=300, bbox_inches='tight')
    # Display the plot
    plt.show()

def heatmap_for_library_configuration(project, ndrivers, napis):
    coverage_datas = get_coverage_datas_for_configuration(
        project, ndrivers, napis)
    draw_figure(project, coverage_datas)


def heatmap_for_library_drivers(project, list_of_drivers):
    coverage_datas = get_coverage_datas_for_drivers(project, list_of_drivers)
    draw_figure(project, coverage_datas)

def get_driver_list(inputfile):

    drv = []

    # file format: driver1 ndriver napi
    with open(inputfile, 'r') as f:
        for l in f:
            if l:
                driver, ndriver, napi = l.split(" ")
                drv += [(driver, int(ndriver), int(napi))]

    return drv



if __name__ == "__main__":
    

    parser = argparse.ArgumentParser(description='Produce heat-map')
    parser.add_argument('--target', '-t', type=str, 
                        help='Target to analyse', required=True)
    subparsers = parser.add_subparsers(help='sub-command help', 
            dest="mode")
    

    # create the parser for the "a" command

    parser_a = subparsers.add_parser('library', 
            help='Heat map per library and configuration')
    parser_a.add_argument('--ndriver', type=int, help='N. Drivers')
    parser_a.add_argument('--napis', type=int, help='N. APIs')

    # create the parser for the "b" command

    parser_b = subparsers.add_parser('custom',
            help='Heat map with custom drivers')
    parser_b.add_argument('--inputfile', type=str, help='Input file')

    args = parser.parse_args()

    # print(args)

    target = args.target

    if args.mode == "library":
        napis = args.napis
        ndrivers = args.ndrivers
        heatmap_for_library_configuration(target, ndrivers, napis)
    else:
        driver_list = get_driver_list(args.inputfile)
        heatmap_for_library_drivers(target, driver_list)