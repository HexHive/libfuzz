# How to include a new Traget Library in the project

Any target should define these scripts:

- `./preinstall.sh` -> usually `apt update && apt install` packets
- `./fetch.sh` -> clone/copy a repo inside `/libfuzzpp/targets/${TARGET}/repo` inside the Docker`
- `/build_library.sh` -> build the library against the fuzzer, remember to `source ${FUZZER}/instrument.sh`
- `./build_driver.sh` -> build the driver against the fuzzer, remember to `source ${FUZZER}/instrument.sh`
- `./analysis.sh` -> run the analysis

Remember the drivers' source code is in `$SHARED/drivers/` and the compilation output should be placed into `$OUT/$PROGRAM`.

## How do I prepare my TARGET?

The target libraries has a bit tricky composition because it is handled by the Docker container and the host. We divide the explanation in two steps:

### Docker container things

The target library must be compiled and fuzzed in the container, and it is done in two sub-steps. Specifically, we need:

step 1) `./build_library.sh`:  
This script builds the library **without** the drivers. The script is run at Docker building time. Its purpose is only to build the library so that we can complete the compilation with the actual driver we desire to test.

**Remember to include** `source ${FUZZER}/instrument.sh` in your script. `instrument.sh` set the `env` variables to automatically include the fuzzer instrumentation and libraries.

step 2) `./build_driver.sh`:  
This script build the actual driver and is automatically invoked by the `entrypoint` (i.e., `./build_and_run.sh`). It just compiles the driver with the pre-compiled library from `./build_library.sh`.

**Remember to include** `source ${FUZZER}/instrument.sh` in your script. `instrument.sh` set the `env` variables to automatically include the fuzzer instrumentation and libraries.