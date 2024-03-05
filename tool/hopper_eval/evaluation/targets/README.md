# Usage

1. Build Hopper by running `docker build -t hopper ./` in repo root directory.
2. Run `docker run --name hopper_dev --privileged -v $(pwd):/fuzz -it --rm hopper /bin/bash` in same root directory.
3. To run fuzzer and get coverage:

```
cd evaluation/targets
export TARGET=cjson
export TIMEOUT=1h

./start_build.sh
./start_fuzzing.sh
./start_coverage.sh
```
