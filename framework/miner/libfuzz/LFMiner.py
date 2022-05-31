from miner  import Miner, GrammarFeedback, LFBackendDriver

class LFMiner(Miner):

    def __init__(self, working_dir, headers_dir):
        self._working_dir = working_dir
        self._headers_dir = headers_dir
        self._backend = LFBackendDriver(working_dir, headers_dir)
        self._idx = 0

    def test(self, driver) -> GrammarFeedback:

        file_name = f"driver{self._idx}.cc"
        self._idx = self._idx + 1

        # create a pseudo code file
        self._backend.emit(driver, file_name)

        # prented to execute
        print(f"LFMiner EXECUTION OF {file_name}")

        # return the feedback -- empty, then random?
        return GrammarFeedback()