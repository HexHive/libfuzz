from miner  import Miner, GrammarFeedback, MockBackendDriver

class MockMiner(Miner):

    def __init__(self, working_dir):
        self._working_dir = working_dir
        self._backend = MockBackendDriver(working_dir)
        self._idx = 0

    def test(self, driver) -> GrammarFeedback:

        file_name = f"Driver{self._idx}.txt"
        self._idx = self._idx + 1

        # create a pseudo code file
        self._backend.emit(driver, file_name)

        # prented to execute
        print(f"MOCKING EXECUTION OF {file_name}")

        # return the feedback -- empty, then random?
        return GrammarFeedback()