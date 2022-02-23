from fuzzer        import FuzzerConfig

class FuzzerSession:
    def __init__(self, config):

        self._workdir = config.work_dir

        self._dependency_generator = config.dependency_generator
        self._grammar_generator = config.grammar_generator
        self._driver_generator = config.driver_generator

        # list of drivers to fuzz
        self.drivers = []

    def run(self):
        DGraph = self._dependency_generator.create()

        InitGrammar = self._grammar_generator.create(DGraph)

        print(InitGrammar)
        # for e, elem in enumerate(InitGrammar):
        #     print(f"{e} -> {elem} \w {len(InitGrammar.get_expansion_rules(elem))} elements")

        print("TODO: generate initial drivers")

        print("TODO: loop and fuzz the drivers")
        while self.drivers:
            driver = drivers.pop()
            print("TODO: fuzz the driver")
            print("TODO: get fuzzing feedback")
            print("TODO: update grammar")
            print("TODO: generate new fuzzers")

