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

        self.variables = []
        for idx in range(n_element):
            self.variables.append(Variable.Variable(f"{token}_{idx}", idx, self))

    def __getitem__(self, key):
        return self.variables[key]

    def __setitem__(self, key, value):
        self.variables[key]= value

    def get_type(self):
        return self.type

    def get_token(self):
        return self.token

    def get_number_elements(self):
        return self.n_element

    def get_address(self):
        if self.n_element == 0:
            raise Exception(f"Can't get address from an empty buffer")

        return self.variables[0].get_address()