from miner  import Miner, FeedbackTest
from backend import BackendDriver

class MockMiner(Miner):

    def __init__(self, backend: BackendDriver):
        self._backend = backend
        # self._executor = executor

    def test(self, driver) -> FeedbackTest:
        print("[TODO] I run the test!")
        return FeedbackTest()