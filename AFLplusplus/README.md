# Goal of the custom AFLplusplus in LibFuzz++

TO BE CONTINUE.....

## How to build AFLplusplus
```
cd /AFLplusplus_path
make source-only
```
If you want to debug AFLplusplus code
```shell
make source-only DEBUG=1
```

### CPU binding in docker
Docker can only detect one CPU inside a container, if two container bind the same CPU, it will
make the CapFuzz very slow when you launch them in parallel. The most easy solution is removing
the binding on the CPU:
```shell
export AFL_NO_AFFINITY=1
```

## Usage
### Build
```shell
cd /AFLplusplus_path
make source-only NO_SPLICING=1
```
The reason why we used `NO_SPLICING=1` is: we don't do delete or insert during the mutation, because we need to keep
the seeds' size fixed

### Use AFL_FIXED_SEED_SIZE to fix the seed size

We provide a flag called `AFL_FIXED_SEED_SIZE` to fix the seed size during the mutation, it can guarantee the 
size of the seed will not be changed.

User just need to add `AFL_FIXED_SEED_SIZE` at the beginning of the afl command line, for example:
```shell
AFL_FIXED_SEED_SIZE AFLplusplus/afl-fuzz -m none -i input_dir/ -o out_put_dir -- /binary_path
```
