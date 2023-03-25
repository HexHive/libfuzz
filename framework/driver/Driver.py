from typing import List, Set, Dict, Tuple, Optional
from .ir import Statement

class Driver:
    statements:     List[Statement]
    clean_up_sec:   List[Statement]
    counter_size:   List[int]

    def __init__(self, statements, context):
        self.statements = statements
        self.context = context
        self.clean_up_sec = []
        self.counter_size = []

    def __iter__(self):
        for s in self.statements:
            yield s
 
    def get_input_size(self):
        # the size if estimated at bits, we transform it into bytes
        return int(self.context.get_allocated_size()/8)
    
    def add_clean_up(self, clean_up_sec) -> 'Driver':
        self.clean_up_sec = clean_up_sec
        return self

    def add_counter_size(self, counter_size) -> 'Driver':
        self.counter_size = [int(c) for c in counter_size]
        return self

    def get_counter_size(self) -> List[int]:
        return self.counter_size