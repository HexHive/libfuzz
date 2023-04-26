from framework.generator import Configuration

# test_dir = "simplelibrary"
test_dir = "cbor"

c = Configuration(f"/workspaces/libfuzz/regression_tests/java_analysis/test/{test_dir}/generator.toml")
f = c.factory
f.create_random_driver()