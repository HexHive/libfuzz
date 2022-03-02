from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod

from backend import BackendDriver
from . import FeedbackTest

class Miner(ABC):

    @abstractmethod
    def __init__(self, backed: BackendDriver):
        pass

    @abstractmethod
    def test(self, driver) -> FeedbackTest:
        pass