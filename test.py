from framework.generator import Configuration

test_dir = "jackson-core"
# test_dir = "cbor"

c = Configuration(f"/workspaces/libfuzz/regression_tests/java_analysis/test/{test_dir}/generator.toml")
f = c.factory

b = c.backend
b.emit_driver(f.create_random_driver(), b.get_name())