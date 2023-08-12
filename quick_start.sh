(TARGET=libtiff TIMEOUT=1h; cd docker && ./run_analysis.sh && ./run_drivergeneration.sh &&  ./run_fuzzing.sh && ./run_coverage.sh)
(TARGET=cpu_features TIMEOUT=1h; cd docker && ./run_analysis.sh && ./run_drivergeneration.sh &&  ./run_fuzzing.sh && ./run_coverage.sh)
