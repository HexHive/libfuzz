from fuzzer         import FuzzerConfig, Pool

class FuzzerSession:
    def __init__(self, config):

        self._workdir = config.work_dir

        self._dependency_generator  = config.dependency_generator
        self._grammar_generator     = config.grammar_generator
        self._driver_generator      = config.driver_generator
        self._miner                 = config.miner
        self._pool                  = config.pool

    def run(self):
        DGraph = self._dependency_generator.create()

        InitGrammar = self._grammar_generator.create(DGraph)

        # InitGrammar.pprint()

        while not self._pool.full():
            self._pool.add_driver(self._driver_generator.create_random_driver(InitGrammar))

        while not self._pool.empty():
            driver = self._pool.pop()
            f = self._miner.test(driver)
            # print("TODO: get fuzzing feedback")
            # print("TODO: update grammar")
            # print("TODO: generate/mutate new fuzzers")

            # TODO: just for debug/develop
            # break