import numpy as np
import csv, json, os

def sig(x):
    return 1/(1 + np.exp(-x))
    
def calc_score(cov, n_crashes, n_unicrsh):
    # return cov * sig(n_unicrsh) / sig(n_crashes)
    return cov / (1 + n_unicrsh)

def load_report(report, rootdir = None):
    libraries = {}

    with open(report) as csvfile:
        spamreader = csv.reader(csvfile, delimiter=',')

        next(spamreader)
        for row in spamreader:
            lib = row[0]
            drvs = libraries.get(lib, [])
            drvs += [get_driver(row[1:], rootdir, lib)]
            libraries[lib] = drvs

    return libraries


def p2f(x):
    return float(x.strip('%'))/100

def get_driver(raw_values, rootdir = None, lib = None):
    driver_id = raw_values[0]
    n_drivers = raw_values[1]
    n_apis = raw_values[2]
    # do not need this?
    # n_iter = raw_values[3]
    cov = p2f(raw_values[4])
    # no need
    # libcov = raw_values[5]
    n_crashes = int(raw_values[6])
    n_unicrsh = int(raw_values[7])

    score = calc_score(cov, n_crashes, n_unicrsh)

    metadata = {}
    if rootdir is not None and lib is not None:
        metadata_file =  os.path.join(rootdir, 
                                      f"workdir_{n_drivers}_{n_apis}", 
                                      lib, "metadata", 
                                      f"{driver_id}.meta"
                                      )
        with open(metadata_file) as fp:
            metadata = json.load(fp)

    return {"driver": driver_id, 
            "n_drivers": n_drivers,
            "n_apis": n_apis,
            "cov": cov,
            "n_crashes": n_crashes,
            "n_unicrsh": n_unicrsh,
            "score": score,
            "metadata": metadata}