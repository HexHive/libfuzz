from abc import ABC, abstractmethod

from . import Symbol, NonTerminal

class Terminal(Symbol):
    def __init__(self, name):
        self.name = name

    def convertToNonTerminal(self):
        return NonTerminal(self.name)    
