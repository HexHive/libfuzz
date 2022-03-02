from miner  import Miner, FeedbackTest, MockBackendDriver

class MockMiner(Miner):

    def __init__(self):
        self._backend = MockBackendDriver()

    def test(self, driver) -> FeedbackTest:

        # create a pseudo code file
        

        # prented to execute

        # return the feedback
        return FeedbackTest()