from miner  import Miner, FeedbackTest
from backend import BackendDriver

class PseudocodeMiner(Miner):

    def __init__(self, backend: BackendDriver):
        self._backend = backend

    def test(self, driver) -> FeedbackTest:
        print("[TODO] I run the test!")
        return FeedbackTest()