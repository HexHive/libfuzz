#!/bin/bash


echo "[INFO] COVERAGE METRICS: ${TARGET_NAME}"



PROJECT_COVERAGE=${LIBFUZZ}/workdir/${TARGET_NAME}/coverage_data
DRIVER_FOLDER=${LIBFUZZ}/workdir/${TARGET_NAME}/drivers
REPO="/home/libfuzz/library/repo"


rm -Rf ${PROJECT_COVERAGE} || true
mkdir -p ${PROJECT_COVERAGE}

FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -type f -executable)"
SOURCES="$(find $REPO -iname '*.h' -or -iname '*.cpp' -or -iname '*.c' -or -iname '*.cc')"


for d in $FUZZ_TARGETS
do
    echo $d
    DRIVER_NAME=$(basename $d)
    echo "COVERAGE: ${DRIVER_NAME}"

    DRIVER_COVERAGE=${PROJECT_COVERAGE}/${DRIVER_NAME}
    DRIVER_COR=${LIBFUZZ}/workdir/${TARGET_NAME}/corpus_new/${DRIVER_NAME}
    DRIVER_CORMIN=${LIBFUZZ}/workdir/${TARGET_NAME}/corpus_mini/${DRIVER_NAME}
    mkdir -p $DRIVER_CORMIN
    mkdir -p $DRIVER_COVERAGE

    $d -merge=1 $DRIVER_CORMIN $DRIVER_COR

    PROFILE_BINARY=${DRIVER_FOLDER}/../profiles/${DRIVER_NAME}_profile

    LLVM_PROFILE_FILE="${DRIVER_NAME}.profraw" $PROFILE_BINARY -runs=0 $DRIVER_CORMIN
    mv ${DRIVER_NAME}.profraw $PROJECT_COVERAGE
    llvm-profdata-12 merge -sparse $PROJECT_COVERAGE/${DRIVER_NAME}.profraw -o $PROJECT_COVERAGE/${DRIVER_NAME}.profdata
    llvm-cov-12 show $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata > show
    llvm-cov-12 report $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata > report
    llvm-cov-12 report -show-functions $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata $SOURCES > functions
    llvm-cov-12 export -format=text $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata > export.json
    mv show $DRIVER_COVERAGE
    mv report $DRIVER_COVERAGE
    mv functions $DRIVER_COVERAGE
    mv export.json $DRIVER_COVERAGE
done

OBJECTS=""
for d in $FUZZ_TARGETS; do
    llvm-profdata-12 merge -sparse $PROJECT_COVERAGE/*.profdata -o $PROJECT_COVERAGE/merged.profdata
    DRIVER_NAME=$(basename $d)
    PROFILE_BINARY=${DRIVER_FOLDER}/../profiles/${DRIVER_NAME}_profile
    if [[ -z $OBJECTS ]]; then
        # The first object needs to be passed without -object= flag.
        OBJECTS="$PROFILE_BINARY"
    else
        OBJECTS="$OBJECTS -object=$PROFILE_BINARY"
    fi
done
llvm-cov-12 show $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata > show
llvm-cov-12 report $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata > report
llvm-cov-12 report -show-functions $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata $SOURCES > functions
mv show $PROJECT_COVERAGE
mv report $PROJECT_COVERAGE
mv functions $PROJECT_COVERAGE
