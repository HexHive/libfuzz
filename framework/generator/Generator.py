from driver.ir import ApiCall
class Generator:
    def __init__(self, config):
        config.build_data_layout()
        config.build_condition_manager()

        self._workdir = config.work_dir

        self._factory   = config.factory
        self._backend   = config.backend
        self._pool      = config.pool
        
    def run(self):
        # print("Cleaning previous drivers...")
        # shutil.rmtree(self._backend.working_dir + "/*")
        # shutil.rmtree(self._backend.seeds_dir + "/*")

        print("Generating drivers...")

        while not self._pool.full():
            self._pool.add_driver(self._factory.create_random_driver())
        print(f"I have done {len(self._pool)} drivers!")

        api_freq = dict([(x, 0) for x in self._factory.dependency_graph.keys()])
        dist_apis = set()

        while not self._pool.empty():
            driver = self._pool.pop()

            driver_name = self._backend.get_name()

            print(f"Storing driver: {driver_name}") 
            self._backend.emit_driver(driver, driver_name)

            print(f"Storing seeds for: {driver_name}")
            self._backend.emit_seeds(driver, driver_name)

            for s in driver.statements:
                if isinstance(s, ApiCall):
                    api = s.original_api
                    api_freq[api] = api_freq.get(api, 0) + 1 
                    dist_apis.add(api)
