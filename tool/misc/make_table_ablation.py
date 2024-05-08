#!/usr/bin/env python3

import argparse

def parse(report_part):

    s = {}

    with open(report_part) as f:
        lib = None
        for l in f:
            if not l:
                continue

            if l[0] == '\t':
                if lib is None:
                    raise Exception("lib unset at: {l}")

                x = s[lib]
                
                l = l.strip()

                if l.startswith("cov >  0%:"):
                    x["cov>0"] = l.split()[-1]
                elif l.startswith("cov > 10%:"):
                    x["cov>10"] = l.split()[-1]
                elif l.startswith("#crashes (cov != 0):"):
                    x["#crash"] = l.split()[-1]

            else:
                lib = l.strip()[:-1]
                s[lib] = {}

    return s

def win(tkn, a, b):
    an = float(a.replace("%",""))
    bn = float(b.replace("%",""))
    if an > bn:
        return f"\\textbf{{{tkn}}}"
    return tkn

def _main():
    parser = argparse.ArgumentParser(description='Produce table for ablation study')
    parser.add_argument('--full', '-f', required=True)
    parser.add_argument('--part', '-p', required=True)

    args = parser.parse_args()
    
    full = args.full
    part = args.part

    full_s = parse(full)
    part_s = parse(part)

    for lib in sorted(full_s.keys()):
        f = full_s[lib]
        p = part_s[lib]

        # from IPython import embed; embed(); exit(1)

        r = [lib.replace("_", "\_")]
        r += [win(f["cov>0"].replace("%", "\%"), f["cov>0"], p["cov>0"])]
        r += [win(p["cov>0"].replace("%", "\%"), p["cov>0"], f["cov>0"])]
        r += [win(f["cov>10"].replace("%", "\%"), f["cov>10"], p["cov>10"])]
        r += [win(p["cov>10"].replace("%", "\%"), p["cov>10"], f["cov>10"])]

        print(" & ".join(r) + " \\\\")

    # print("end!")
    # from IPython import embed; embed(); exit(1)

if __name__ == "__main__":
    _main()