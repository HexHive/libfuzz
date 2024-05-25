#!/bin/bash

echo "[INFO] COVERAGE METRICS: ${TARGET_NAME}"


REPO="/home/libfuzz/library/repo"


rm -Rf ${PROJECT_COVERAGE} || true
mkdir -p ${PROJECT_COVERAGE}

SOURCES="$(find $REPO -iname '*.h' -or -iname '*.cpp' -or -iname '*.c' -or -iname '*.cc')"
if [[ -z ${GRAMMAR_MODE} ]]; then
    DRIVER_PATH_REGEX="\/workspaces\/libfuzz\/workdir\/.*\/drivers\/.*\.cc"
else
    DRIVER_PATH_REGEX="\/workspaces\/libfuzz\/fuzzing_campaigns\/workdir_X_X\/${TARGET_NAME}/iter_.*\/drivers\/.*\.cc"
fi


if [[ $TOTAL_LIBRARY_COVERAGE ]]; then

    if [[ -z ${GRAMMAR_MODE} ]]; then
        MERGED_PROFDATAS="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/coverage_data/iter_*/merged.profdata)"
        PROFILES="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/profiles/*_profile)"
    else
        MERGED_PROFDATAS="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/iter_*/coverage_data/merged.profdata)"
        PROFILES="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/iter_*/profiles/*_profile)"
    fi

    mkdir -p fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    ${LLVM_DIR}/bin/llvm-profdata merge -sparse $MERGED_PROFDATAS -o fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata

    OBJECTS=""
    for profile in $PROFILES; do
        if [[ -z $OBJECTS ]]; then
            # The first object needs to be passed without -object= flag.
            OBJECTS="$profile"
        else
            OBJECTS="$OBJECTS -object=$profile"
        fi
    done

    ${LLVM_DIR}/bin/llvm-cov show $OBJECTS -instr-profile=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata > show
    ${LLVM_DIR}/bin/llvm-cov report $OBJECTS -instr-profile=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
    ${LLVM_DIR}/bin/llvm-cov report -show-functions $OBJECTS -instr-profile=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions

    mv show fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    mv report fuzzing_campaigns/total_library_coverage/${TARGET_NAME}
    mv functions fuzzing_campaigns/total_library_coverage/${TARGET_NAME}

    for i in $( eval echo {1..$ITERATIONS} ); do
        TARGET_ITER=fuzzing_campaigns/total_library_coverage/${TARGET_NAME}/iter_${i}

        if [[ -z ${GRAMMAR_MODE} ]]; then
            MERGED_PROFDATAS="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/coverage_data/iter_${i}/merged.profdata)"
        else
            MERGED_PROFDATAS="$(ls -d fuzzing_campaigns/*/${TARGET_NAME}/iter_${i}/coverage_data/merged.profdata)"
        fi

        mkdir -p ${TARGET_ITER}
        ${LLVM_DIR}/bin/llvm-profdata merge -sparse $MERGED_PROFDATAS -o ${TARGET_ITER}/merged.profdata

        ${LLVM_DIR}/bin/llvm-cov show $OBJECTS -instr-profile=${TARGET_ITER}/merged.profdata > show
        ${LLVM_DIR}/bin/llvm-cov report $OBJECTS -instr-profile=${TARGET_ITER}/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
        ${LLVM_DIR}/bin/llvm-cov report -show-functions $OBJECTS -instr-profile=${TARGET_ITER}/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions

        mv show ${TARGET_ITER}/
        mv report ${TARGET_ITER}/
        mv functions ${TARGET_ITER}/
    done

    exit 0
fi


if [[ $TOTAL_DRIVER_COVERAGE ]]; then
    DRIVER_FOLDER=${PROJECT_FOLDER}/drivers
    FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -type f -executable)"
    for d in $FUZZ_TARGETS; do
        DRIVER_NAME=$(basename $d)
        if [[ -z ${GRAMMAR_MODE} ]]; then
            DRIVER_PROFDATAS="$(ls -d ${PROJECT_FOLDER}/coverage_data/iter_*/${DRIVER_NAME}.profdata)"
        else
            DRIVER_PROFDATAS="$(ls -d ${PROJECT_FOLDER}/iter_*/coverage_data/${DRIVER_NAME}.profdata)"
        fi
        mkdir -p ${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}
        ${LLVM_DIR}/bin/llvm-profdata merge -sparse $DRIVER_PROFDATAS -o ${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}/merged.profdata

        PROFILE_BINARY=${PROJECT_FOLDER}/profiles/${DRIVER_NAME}_profile

        ${LLVM_DIR}/bin/llvm-cov show $PROFILE_BINARY -instr-profile=${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}/merged.profdata > show
        ${LLVM_DIR}/bin/llvm-cov report $PROFILE_BINARY -instr-profile=${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
        ${LLVM_DIR}/bin/llvm-cov report -show-functions $PROFILE_BINARY -instr-profile=${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions

        mv show ${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}
        mv report ${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}
        mv functions ${PROJECT_FOLDER}/coverage_data/${DRIVER_NAME}
    done
    exit 0
fi

if [[ $TOTAL_LIBRARY_COVERAGE_FOR_CONFIGURATION ]]; then
    if [[ -z ${GRAMMAR_MODE} ]]; then
        MERGED_PROFDATAS="$(ls -d ${PROJECT_FOLDER}/coverage_data/iter_*/merged.profdata)"
        PROFILES="$(ls -d ${PROJECT_FOLDER}/profiles/*_profile)"
    else
        MERGED_PROFDATAS="$(ls -d ${PROJECT_FOLDER}/iter_*/coverage_data/merged.profdata)"
        PROFILES="$(ls -d ${PROJECT_FOLDER}/iter_*/profiles/*_profile)"
    fi    
    mkdir -p ${PROJECT_FOLDER}/coverage_data/total
    ${LLVM_DIR}/bin/llvm-profdata merge -sparse $MERGED_PROFDATAS -o ${PROJECT_FOLDER}/coverage_data/total/merged.profdata

    OBJECTS=""
    for profile in $PROFILES; do
        if [[ -z $OBJECTS ]]; then
            # The first object needs to be passed without -object= flag.
            OBJECTS="$profile"
        else
            OBJECTS="$OBJECTS -object=$profile"
        fi
    done

    ${LLVM_DIR}/bin/llvm-cov show $OBJECTS -instr-profile=${PROJECT_FOLDER}/coverage_data/total/merged.profdata > show
    ${LLVM_DIR}/bin/llvm-cov report $OBJECTS -instr-profile=${PROJECT_FOLDER}/coverage_data/total/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
    ${LLVM_DIR}/bin/llvm-cov report -show-functions $OBJECTS -instr-profile=${PROJECT_FOLDER}/coverage_data/total/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions

    mv show ${PROJECT_FOLDER}/coverage_data/total
    mv report ${PROJECT_FOLDER}/coverage_data/total
    mv functions ${PROJECT_FOLDER}/coverage_data/total
    exit 0
fi


FUZZ_TARGETS="$(find ${DRIVER_FOLDER} -type f -executable)"
for d in $FUZZ_TARGETS
do
    echo $d
    DRIVER_NAME=$(basename $d)
    echo "COVERAGE: ${DRIVER_NAME}"

    DRIVER_COVERAGE=${PROJECT_COVERAGE}/${DRIVER_NAME}
    DRIVER_COR=${CORPUS_FOLDER}/${DRIVER_NAME}
    mkdir -p $DRIVER_COVERAGE

    PROFILE_BINARY=${DRIVER_FOLDER}/../profiles/${DRIVER_NAME}_profile

    INPUTS="$(ls $DRIVER_COR)"
    for input in $INPUTS; do
        LLVM_PROFILE_FILE="${DRIVER_NAME}-${input}.profraw" timeout -k 10s 1m $PROFILE_BINARY -runs=0 $DRIVER_COR/$input
        # the coverage produces a timeout, we might consider it as a timeout crash
        if [[ $? -ne 0 ]]; then
            echo "[INFO] Error while computing the coverage, moving to crashes"
            CRASH_FOLDER="${CORPUS_FOLDER/corpus_new/crashes}"
            cp $DRIVER_COR/$input ${CRASH_FOLDER}/${DRIVER_NAME}/coverr-$input
        fi
        mv ${DRIVER_NAME}-${input}.profraw $PROJECT_COVERAGE
    done

    ${LLVM_DIR}/bin/llvm-profdata merge -sparse $PROJECT_COVERAGE/${DRIVER_NAME}-*.profraw -o $PROJECT_COVERAGE/${DRIVER_NAME}.profdata
    rm -f $PROJECT_COVERAGE/${DRIVER_NAME}-*.profraw
    ${LLVM_DIR}/bin/llvm-cov show $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata > show
    ${LLVM_DIR}/bin/llvm-cov report $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
    ${LLVM_DIR}/bin/llvm-cov report -show-functions $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions
    ${LLVM_DIR}/bin/llvm-cov export -format=text $PROFILE_BINARY -instr-profile=$PROJECT_COVERAGE/${DRIVER_NAME}.profdata > export.json
    mv show $DRIVER_COVERAGE
    mv report $DRIVER_COVERAGE
    mv functions $DRIVER_COVERAGE
    mv export.json $DRIVER_COVERAGE
done

OBJECTS=""
for d in $FUZZ_TARGETS; do
    ${LLVM_DIR}/bin/llvm-profdata merge -sparse $PROJECT_COVERAGE/*.profdata -o $PROJECT_COVERAGE/merged.profdata
    DRIVER_NAME=$(basename $d)
    PROFILE_BINARY=${DRIVER_FOLDER}/../profiles/${DRIVER_NAME}_profile
    if [[ -z $OBJECTS ]]; then
        # The first object needs to be passed without -object= flag.
        OBJECTS="$PROFILE_BINARY"
    else
        OBJECTS="$OBJECTS -object=$PROFILE_BINARY"
    fi
done
${LLVM_DIR}/bin/llvm-cov show $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata > show
${LLVM_DIR}/bin/llvm-cov report $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata -ignore-filename-regex=$DRIVER_PATH_REGEX > report
${LLVM_DIR}/bin/llvm-cov report -show-functions $OBJECTS -instr-profile=$PROJECT_COVERAGE/merged.profdata $SOURCES -ignore-filename-regex=$DRIVER_PATH_REGEX > functions
mv show $PROJECT_COVERAGE
mv report $PROJECT_COVERAGE
mv functions $PROJECT_COVERAGE
