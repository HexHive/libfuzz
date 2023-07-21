#!/bin/bash
set -e

##
# Pre-requirements:
# - env TARGET: path to target work dir
# - env OUT: path to directory where artifacts are stored
# - env CC, CXX, FLAGS, LIBS, etc...
##

# if [ ! -d "$TARGET/repo" ]; then
#     echo "fetch.sh must be executed first."
#     exit 1
# fi

WORK="$TARGET/work"

cd "$TARGET/repo"

CXX=$LLVM_DIR/bin/clang++
CC=$LLVM_DIR/bin/clang

echo "Compiling: ${DRIVER_FOLDER}/${DRIVER}.cc"
mkdir -p ${DRIVER_FOLDER}/../profiles


# [TAG] FIRST LOOP FOR COMPILATION!!!
for d in `ls ${DRIVER_FOLDER}/${DRIVER}.cc`
do
    echo "Driver: $d"
    DRIVER_NAME=$(basename $d)
    # [TAG] THIS STEP MUST BE ADAPTED FOR EACH LIBRARY
    # Compile driver for fuzzing
    $CXX -g -std=c++11  -fsanitize=fuzzer,address -I/${TARGET}/work/include \
        $d ${TARGET}/work/lib/libminijail.pie.a \
        -lcap -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${d%%.*}"

    # Compile driver for coverage
    $CXX -g -std=c++11  -fsanitize=fuzzer -fprofile-instr-generate -fcoverage-mapping \
        -I/${TARGET}/work/include $d ${TARGET}/work/lib/libminijail_profile.pie.a \
        -lcap -Wl,-Bstatic -llzma -Wl,-Bdynamic -lstdc++ -o "${DRIVER_FOLDER}/../profiles/${DRIVER_NAME%%.*}_profile"
done
