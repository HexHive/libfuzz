from abc import ABC, abstractmethod

from . import Symbol, Terminal

class NonTerminal(Symbol):
    def __init__(self, name):
        self.name = name

    def convertToTerminal(self):
        return Terminal.Terminal(self.name)