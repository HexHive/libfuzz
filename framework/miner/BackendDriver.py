from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod

# from . import Type

class BackendDriver(ABC):

    @abstractmethod
    def __init__(self, working_dir):
        pass

    @abstractmethod
    def emit(self) -> str:
        pass
    