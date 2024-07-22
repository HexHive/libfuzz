import numpy as np
from sklearn.cluster import AffinityPropagation
from Levenshtein import distance as levenshtein_distance

import sys

# List of strings to cluster
# strings = [
#     "apple", "apples", "orange", "oranges", "banana", "bananas",
#     "car", "cars", "bicycle", "bicycles"
#]

strings = []

with open(sys.argv[1], 'r') as fp:
    for l in fp:
        la = l.strip().split(":")
        if la[2] != "POSITIVE":
            continue

        strings += [la[1].split(";")]

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
    print(f"Cluster {cluster_id}:")
    for string_id in np.where(clusters == cluster_id)[0]:
        print(f"    {strings[string_id]}")
        break

