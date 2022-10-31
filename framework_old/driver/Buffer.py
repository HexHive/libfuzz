from abc import ABC, abstractmethod
from typing import List, Set, Dict, Tuple, Optional

from . import Statement, Type, Variable

class Buffer:
    # variables:  List[Variable]
    n_element:  int
    type:       Type

    def __init__(self, token, n_element, type):
        self.token = token
        self.n_element = n_element
        self.type = type

        self.variables = {}

    def __getitem__(self, key):
        if key < 0 or key >= self.n_element:
            raise KeyError

        self._init(key)

        return self.variables[key]

    def __setitem__(self, key, value):
        if key < 0 or key >= self.n_element:
            raise KeyError

        self.variables[key] = value

    def get_type(self):
        return self.type

    def get_token(self):
        return self.token

    def get_number_elements(self):
        return self.n_element

    def _init(self, key):
        # lazy init, I set the variable if requested by somebody
        if key not in self.variables:
                self.variables[key] = Variable.Variable(f"{self.token}_{key}", key, self)

    def get_address(self):
        if self.n_element == 0:
            raise Exception(f"Can't get address from an empty buffer")

        self._init(0)
        return self.variables[0].get_address()

    def get_allocated_size(self):
        return self.n_element * self.type.get_size()
