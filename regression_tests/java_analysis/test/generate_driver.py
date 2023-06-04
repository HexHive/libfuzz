import sys
sys.path.append("../../..")
from framework.generator import Configuration

if len(sys.argv) != 3:
    print("libDir and driverNum needs to be specified")
    exit()

c = Configuration(f"/home/lizhaorui/libfuzz/regression_tests/java_analysis/test/{sys.argv[1]}/generator.toml")
b = c.backend
f = c.factory

driver_num = 0
while True:
    try:
        d = f.create_random_driver()
        n = b.get_name()
        b.emit_driver(d, n)
        driver_num += 1
    except Exception as e:
        print(e)

    if driver_num == int(sys.argv[2]):
        break