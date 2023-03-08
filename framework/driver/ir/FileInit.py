from abc import ABC, abstractmethod
from typing import List, Set, Dict, Tuple, Optional

from . import Statement, Type, Variable, Buffer

class FileInit(Statement):
    buffer:     Buffer
    len_var:    Variable

    def __init__(self, buffer, len_var):
        super().__init__()
        self.buffer = buffer
        self.len_var = len_var

    # for an element, the hash is just the key + type
    def __hash__(self):
        return hash(self.token + str(self.__class__.__name__))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.buffer.get_token()})"

    def get_buffer(self):
        return self.buffer

    def get_len_var(self):
        return self.len_var