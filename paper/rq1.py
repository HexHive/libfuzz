#!/usr/bin/env python3
from scipy.interpolate import make_interp_spline, BSpline
import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl
font = {'family' : 'normal',
        'weight' : 'ultralight',
        'size'   : 15}

mpl.rc('font', **font)
mpl.rcParams['text.usetex'] = True
mpl.rcParams['text.latex.preamble'] = [r'\usepackage{amsmath}']
# Data
generations = list(map(lambda x: r"\textbf{"+x+"}", ['24h', '18h', '12h', '6h']))
generations.reverse() 
data = {}
data["c_ares"] = [55.29, 50.88, 49.06, 52.65]
data["cjson"] = [75.34, 73.20, 71.52, 72.68]
data["cpu_features"] = [19.22, 19.22, 19.22, 19.22]
data["libaom"] = [10.98, 10.57, 5.51, 11.77]
data["libhtp"] = [26.74, 25.07, 16.34, 17.37]
data["libpcap"] = [40.93, 40.81, 37.48, 38.03]
data["libtiff"] = [14.32, 14.99, 12.40, 17.42]
data["libvpx"] = [8.24, 8.90, 3.71, 7.59]
data["minijail"] = [18.45, 15.48, 16.03, 16.07]
data["pthreadpool"] = [50.44, 44.21, 36.42, 40.42]
data["zlib"] = [58.32, 58.83, 46.26, 55.01]




# Plotting
fig, ax = plt.subplots(figsize=(10, 6))

l = ['solid', 'dotted']
colors = ['b', 'g', 'r', 'c', 'm', 'k', 'peru']
markers = ['o', 'X', '*']
xnew = np.linspace(6, 24, 300)  
i = 0
for(lib, values) in data.items():
    values.reverse()
    values = values / np.max(values) * 100
    ax.plot(generations, values, label=r"\texttt{"+lib+r"}", marker=markers[i%3], linestyle=l[i%2], color=colors[i%7], markersize=5)
    i += 1

# Labels and Title
#ax.set_ylim(ymin=0)
plt.xlabel(r"$\mathbf{T_{gen}}$")
plt.ylabel(r'\textbf{Normalized Coverage [\%]}')
fig.canvas.draw()
labels = [item.get_text() for item in ax.get_yticklabels()]
m = map(lambda x: x.replace("default", "bf"), labels)
ax.set_yticklabels(list(m))
plt.legend(bbox_to_anchor=(.7, 0.69), loc='upper left')

# Show plot
plt.tight_layout()
plt.savefig('rq1.png')
plt.savefig('rq1.pdf')
plt.show()
