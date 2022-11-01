import random, copy, re
from typing import List, Set, Dict, Tuple, Optional
from abc import ABC, abstractmethod

from grammar import Grammar, Terminal, NonTerminal
from common import Utils, Api, Arg
from driver import Driver, Context
from driver.ir import Statement, ApiCall, BuffDecl, Type, PointerType, Variable

class Factory(ABC):
    concretization_logic: Dict[Terminal, ApiCall]

    @abstractmethod
    def __init__(self):
        pass

    @abstractmethod
    def create_random_driver(self) -> Driver:
        pass