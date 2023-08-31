#!/bin/bash


if [[ $TOTAL_LIBRARY_COVERAGE ]]; then
    MERGED_PROFDATAS="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/coverage_data/iter_*/merged.profdata)"
    mkdir -p fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    llvm-profdata-12 merge -sparse $MERGED_PROFDATAS -o fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata
    PROFILES="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/profiles/*_profile)"

    OBJECTS=""
    for profile in $PROFILES; do
        if [[ -z $OBJECTS ]]; then
            # The first object needs to be passed without -object= flag.
            OBJECTS="$profile"
        else
            OBJECTS="$OBJECTS -object=$profile"
        fi
    done

    llvm-cov-12 show $OBJECTS -instr-profile=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata > show
    llvm-cov-12 report $OBJECTS -instr-profile=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
    llvm-cov-12 report -show-functions $OBJECTS -instr-profile=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions

    mv show fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    mv report fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    mv functions fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    exit 0
fi


echo "[INFO] COVERAGE METRICS: ${TARGET_NAME}"


REPO="/home/libfuzz/library/repo"


rm -Rf ${PROJECT_COVERAGE} || true
mkdir -p ${PROJECT_COVERAGE}

FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -type f -executable)"
SOURCES="$(find $REPO -iname '*.h' -or -iname '*.cpp' -or -iname '*.c' -or -iname '*.cc')"
DRIVER_PATH_REGEX="\/workspaces\/libfuzz\/workdir\/.*\/drivers\/.*\.cc"

for d in $FUZZ_TARGETS
do
    echo $d
    DRIVER_NAME=$(basename $d)
    echo "COVERAGE: ${DRIVER_NAME}"

    DRIVER_COVERAGE=${PROJECT_COVERAGE}/${DRIVER_NAME}
    DRIVER_COR=${CORPUS_FOLDER}/${DRIVER_NAME}
    DRIVER_CORMIN=${CORPUS_FOLDER}/../corpus_mini/${DRIVER_NAME}
    mkdir -p $DRIVER_CORMIN
    mkdir -p $DRIVER_COVERAGE

    $d -merge=1 $DRIVER_CORMIN $DRIVER_COR

    PROFILE_BINARY=${DRIVER_FOLDER}/../profiles/${DRIVER_NAME}_profile

    LLVM_PROFILE_FILE="${DRIVER_NAME}.profraw" $PROFILE_BINARY -runs=0 $DRIVER_CORMIN
    mv ${DRIVER_NAME}.profraw $PROJECT_COVERAGE
    llvm-profdata-12 merge -sparse $PROJECT_COVERAGE/${DRIVER_NAME}.profraw -o $PROJECT_COVERAGE/${DRIVER_NAME}.profdata
    llvm-cov-12 show $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata > show
    llvm-cov-12 report $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
    llvm-cov-12 report -show-functions $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions
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
llvm-cov-12 report $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
llvm-cov-12 report -show-functions $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions
mv show $PROJECT_COVERAGE
mv report $PROJECT_COVERAGE
mv functions $PROJECT_COVERAGE
