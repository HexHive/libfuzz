from abc import ABC, abstractmethod

from . import Symbol

class Terminal(Symbol):
    def __init__(self, name):
        self.name = name

    
