# Running Hopper Campaigns

1. Clone Hopper repo from `https://github.com/FuzzAnything/Hopper` (at the time of writing this @ da5e044 commit)
2. Copy `hopper`, `Dockerfile` and `update_clang.sh` to `Hopper` directory
3. Build Hopper: `docker build -t hopper ./Hopper`
4. `docker run --name hopper_dev --privileged -v $(pwd):/fuzz -it --rm hopper /bin/bash`
5. To run fuzzer and get coverage:

```bash
cd evaluation/targets
export TARGET=cjson
export TIMEOUT=1h

./start_build.sh
./start_fuzzing.sh
./start_coverage.sh
```
