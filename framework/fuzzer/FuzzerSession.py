from fuzzer import FuzzerConfig, Pool
from driver import Driver        

class FuzzerSession:
    def __init__(self, config):

        self._workdir = config.work_dir

        self._dependency_generator  = config.dependency_generator
        self._grammar_generator     = config.grammar_generator
        self._driver_generator      = config.driver_generator
        self._backend               = config.backend
        self._pool                  = config.pool
        self._fuzzer_name           = config.fuzzer_nane
        self._fuzzer_timeout        = config.fuzzer_timeout
        self._target_library        = config.target_library

        self.fuzzwrap               = config.fuzzer_wrapper

    def run(self):
        DGraph = self._dependency_generator.create()

        InitGrammar = self._grammar_generator.create(DGraph)

        # InitGrammar.pprint()

        while not self._pool.full():
            self._pool.add_driver(self._driver_generator.create_random_driver(InitGrammar))

        while not self._pool.empty():
            driver = self._pool.pop()

            driver_name = self._backend.get_name()

            print(f"Generating driver: {driver_name}")
            self._backend.emit_driver(driver, driver_name)

            print(f"Generating seeds for: {driver_name}")
            self._backend.emit_seeds(driver, driver_name)

            print(f"Fuzzing: {driver_name}")
            self.fuzz_one(driver_name)

            # for debug, eventually
            print("debug!")
            break

    # wrapper to invoke AFL in the Docker
    def fuzz_one(self, driver_name: str):
        
        fuzzwrap = self.fuzzwrap

        # get program (driver) [argument!]

        # get target (library)
        target  = self._target_library
        # get timeout 
        timeout = self._fuzzer_timeout
        # get fuzzer
        fuzzer  = self._fuzzer_name

        # if container does not exist
        if not fuzzwrap.does_image_exist(target):
            # build container for $target
            print("The image does not exist, going to create it!")
            fuzzwrap.build_image(fuzzer, target, timeout)
        
        # fuzz one driver!
        fuzzwrap.fuzz_one(driver_name, target)


