from miner  import Miner, GrammarFeedback, MockBackendDriver

class MockMiner(Miner):

    def __init__(self, working_dir):
        self._working_dir = working_dir

        self._backend = MockBackendDriver(working_dir)

    def test(self, driver) -> GrammarFeedback:

        # create a pseudo code file
        file_name = self._backend.emit(driver)

        # prented to execute
        print(f"MOCKING EXECUTION OF {file_name}")

        # return the feedback -- empty, then random?
        return GrammarFeedback()