from fuzzer        import FuzzerConfig

class FuzzerSession:
    def __init__(self, config):

        self._workdir = config.work_dir

        self._dependency_generator = config.dependency_generator

        self._driver_generator = config.driver_generator

        # list of drivers to fuzz
        self.drivers = []

    def run(self):
        
        print("TODO: generate dependecy graph")

        print("TODO: generate grammar")

        print("TODO: generate initial drivers")

        print("TODO: loop and fuzz the drivers")
        while self.drivers:
            driver = drivers.pop()
            print("TODO: fuzz the driver")
            print("TODO: get fuzzing feedback")
            print("TODO: update grammar")
            print("TODO: generate new fuzzers")

