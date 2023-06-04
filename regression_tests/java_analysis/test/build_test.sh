set -e

libDir=$1

if [ -z "$libDir" ]
then
  echo "libDir is not Specified"
  exit
fi

baseDir="/home/lizhaorui/libfuzz/regression_tests/java_analysis/test"
pomFile="$baseDir/$libDir/pom.xml"
jarDir="$baseDir/$libDir/jars"
jarFile="$baseDir/$libDir/$libDir.jar"
apiListFile="$baseDir/$libDir/minimum_apis.txt"

cd $libDir
# if [ ! -f "$jarFile" ]
# then
#   echo "jarFile does not exist"
#   exit
# fi

if [ ! -f "$pomFile" ]; then
  echo "pom.xml does not exist"
  exit
fi

if [ ! -f "$apiListFile" ]; then
  echo "minimum_apis.txt does not exist"
  exit
fi

mkdir -p $jarDir
# mv $jarFile "$jarDir/"
# mvn dependency:copy-dependencies -DoutputDirectory=jars/

extractorDir="/home/lizhaorui/libfuzz/java_analysis"
extractorClass="analysis.Main"
cd $extractorDir
mvn exec:java -Dexec.mainClass="$extractorClass" -Dexec.args="$baseDir/$libDir $libDir.jar"

configFile="$baseDir/$libDir/generator.toml"
touch $configFile
cat << EOF > $configFile
[analysis]
apis = "$baseDir/$libDir/apis.json"
subtypes = "$baseDir/$libDir/subtypes.json"
minimum_apis = "$baseDir/$libDir/minimum_apis.txt"
builtin_apis = "$baseDir/builtin.json"
builtin_subtypes = "$baseDir/builtin_subtypes.json"

[generator]
policy = "java"
workdir = "$baseDir/$libDir/workdir"
num_seeds = 1
backend = "java_backend"
EOF