set -e

libDir=$1
driverNum=$2
fuzzTime=$3

# ./build_test.sh $libDir
# python3 ./generate_driver.py $libDir $driverNum

jazzerDir="/home/lizhaorui/jazzer"
cd $libDir/workdir/drivers
javac -cp "$jazzerDir/jazzer_standalone.jar:../../jars/*" *.java

classpath="."
for entry in ../../jars/*
do
  classpath="$classpath:$entry"
done

mkdir -p ../../reports

set +e
for ((i=0;i<=driverNum;i++)); do
    $jazzerDir/jazzer --cp="$classpath" --target_class="Driver$i" --keep_going=10 -max_total_time=$fuzzTime --jvm_args="-Xmx4096m:-Xss1024k" --coverage_report=../../reports/"Driver$i"_coverage --coverage_dump=../../reports/"Driver$i".exec
done