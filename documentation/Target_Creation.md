# How to include a new Traget Library in the project

Any target should define these scripts:

- `./preinstall.sh` -> usually `apt update && apt install` packets
- `./fetch.sh` -> clone/copy a repo inside `/libfuzzpp/targets/${TARGET}/repo` inside the Docker`
- `/build_library.sh` -> build the library against the fuzzer, remember to `source ${FUZZER}/instrument.sh`
- `./build_driver.sh` -> build the driver against the fuzzer, remember to `source ${FUZZER}/instrument.sh`

Remember the drivers' source code is in `$SHARED/drivers/` and the compilation output should be placed into `$OUT/$PROGRAM`.