#!python3

import os, sys, argparse
from subprocess import check_output

def dump(output, fName):
    with open(output, 'a') as f:
        f.write(f"{fName}\n")

def _main():

    parser = argparse.ArgumentParser(description='Get exported symbols')
    parser.add_argument('--sharedlibrary', required=True, help='The shared library to analyse')
    parser.add_argument('--output', help='The output file', default='exported_symbols.txt')

    args = parser.parse_args()

    library = args.sharedlibrary
    output = args.output

    out = check_output(["nm", "-D", library])

    for i, l in enumerate(out.decode("utf-8").splitlines()):
        if " T " in l:
            # print(f"I={i}")
            # print(l)
            fName = l.split()[-1]
            dump(output, fName)

    # print(out)    

if __name__ == "__main__":
    _main()