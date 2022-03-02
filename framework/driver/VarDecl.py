from abc import ABC, abstractmethod

from . import Statement, Type, Variable

class VarDecl(Statement):
    variable:   Variable

    def __init__(self, variable):
        super().__init__()
        self.variable   = variable

    # for an element, the hash is just the key + type
    def __hash__(self):
        return hash(self.token + str(self.__class__.__name__))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.variable.get_token()})"