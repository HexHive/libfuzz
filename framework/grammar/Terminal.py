from abc import ABC, abstractmethod

from . import Element

class Terminal(Element):
    def __init__(self, name):
        self.name = name

    
