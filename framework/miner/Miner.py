from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod

from . import FeedbackTest

class Miner(ABC):

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def test(self, driver) -> FeedbackTest:
        pass