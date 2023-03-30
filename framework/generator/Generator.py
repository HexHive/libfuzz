class Generator:
    def __init__(self, config):

        self._workdir = config.work_dir

        self._factory   = config.factory
        self._backend   = config.backend
        self._pool      = config.pool

        config.build_data_layout()

    def run(self):
        print("Generating drivers...")

        while not self._pool.full():
            self._pool.add_driver(self._factory.create_random_driver())
        print(f"I have done {len(self._pool)} drivers!")

        while not self._pool.empty():
            driver = self._pool.pop()

            driver_name = self._backend.get_name()

            print(f"Storing driver: {driver_name}") 
            self._backend.emit_driver(driver, driver_name)

            print(f"Storing seeds for: {driver_name}")
            self._backend.emit_seeds(driver, driver_name)
