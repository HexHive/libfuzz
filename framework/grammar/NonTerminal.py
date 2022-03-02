from abc import ABC, abstractmethod

from . import Symbol

class NonTerminal(Symbol):
    def __init__(self, name):
        self.name = name