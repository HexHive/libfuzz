#!/usr/bin/env python3

import numpy as np
from sklearn.cluster import AffinityPropagation
from Levenshtein import distance as levenshtein_distance

import sys, argparse

# List of strings to cluster
# strings = [
#     "apple", "apples", "orange", "oranges", "banana", "bananas",
#     "car", "cars", "bicycle", "bicycles"
#]

def make_key(drv):
    return "".join(drv)

def _main():
    
    parser = argparse.ArgumentParser(description='Cluster Driver')
    parser.add_argument('-path',  type=str, help='Run generation in debug mode', required=True)

    args = parser.parse_args()
    
    paths = args.path
    
    strings = []

    driver_info = dict()

    with open(paths, 'r') as fp:
        for l in fp:
            la = l.strip().split(":")
            if la[2] != "POSITIVE":
                continue
            
            driver_name = la[0]
            api_seq = la[1].split(";")
            seeds = int(la[3])
            
            key = make_key(api_seq)

            strings += [api_seq]
            driver_info[key] = (seeds, driver_name)

    print(f"num of strings {len(strings)}")

    # from IPython import embed; embed(); exit(1)

    # Compute the similarity matrix
    n = len(strings)
    similarity_matrix = np.zeros((n, n))

    for i in range(n):
        for j in range(n):
            if i != j:
                similarity_matrix[i, j] = -levenshtein_distance(strings[i], strings[j])
            else:
                similarity_matrix[i, j] = 0

    # Affinity Propagation clustering
    affinity_propagation = AffinityPropagation(affinity="precomputed", random_state=0)
    affinity_propagation.fit(similarity_matrix)

    # Display the results
    clusters = affinity_propagation.labels_
    for cluster_id in np.unique(clusters):
        # print(f"Cluster {cluster_id}:")
        cluster_info = []
        for string_id in np.where(clusters == cluster_id)[0]:
            key = make_key(strings[string_id])
            (n_seed, driver_name) = driver_info[key]
            cluster_info += [(n_seed, driver_name, strings[string_id])]
            # print(f"   {driver_name} {strings[string_id]}: {n_seed}")
            # break
            
        for s, d, a in sorted(cluster_info, key=lambda tup: tup[0], reverse=True):
            a_str = ";".join(a)
            print(f"{cluster_id}|{d}|{a_str}|{s}")
            break

if __name__ == "__main__":
    _main()
