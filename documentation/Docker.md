# Docker composition

Here, we describe the Docker structure and its internal workflow.

The Docker is used to fuzz a target library, and the scripts to control it are in `./docker`.
```
+-- docker
    +-- quick_start.sh # utility to build and run the Docker container
    +-- Dockerfile     # control the docker building
    +-- build.sh       # build the docker container
    +-- run.sh         # run the entryoint of the docker container + 
                       # wiring the  shared folder with the host
```

## Dockerfile workflow:

Logically, the `Dockerfile` follows this logic:

```
// Fuzzer
./fetch.sh
./build.sh

// Target
./preinstall.sh
./fetch.sh
./build_library.sh
+-- add: source ${FUZZER}/instrument.sh

// Entry Point
set ./build_and_run.sh
+-- ./build_driver.sh
    +-- add: source ${FUZZER}/instrument.sh
+-- ./run.sh
```

`./docker/build.sh` script kicks the Docker building, i.e., follow `Dockerfile` specification.

`./docker/run.sh` script builds the driver against the target library, map the shared folders with the host, and start fuzzing, i.e., it runs the entry points `./build_and_run.sh`

## Docker important folders

There are three main folders in the Docker containers:
```
+-- /libfuzzpp
|   +-- fuzzers  # contains the fuzzer (usually AFL++)
|   |   +-- build_and_run.sh   # entrypoint
|   |   +-- run.sh             # start actual fuzzing
|   |
|   +-- targets  # contains the library targets
|       +-- ???
|
+-- /libfuzzpp_out
|   +-- ???
|
+-- /libfuzzpp_share
    +-- findings # reports of fuzzer
    +-- drivers  # the driver generator will save shits here
```

The folders are automatically handled by `Dockerfile` and `./docker/run/sh`.