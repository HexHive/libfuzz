from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod

from . import GrammarFeedback

class Miner(ABC):

    @abstractmethod
    def __init__(self, working_dir):
        pass

    @abstractmethod
    def test(self, driver) -> GrammarFeedback:
        pass