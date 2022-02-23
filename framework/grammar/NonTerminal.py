from abc import ABC, abstractmethod

from . import Element

class NonTerminal(Element):
    def __init__(self, name):
        self.name = name