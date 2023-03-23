from typing import List, Set, Dict, Tuple, Optional
from .ir import Statement

class Driver:
    statements:     List[Statement]
    clean_up_sec:   List[Statement]

    def __init__(self, statements, context):
        self.statements = statements
        self.context = context
        self.clean_up_sec = []

    def __iter__(self):
        for s in self.statements:
            yield s
 
    def get_input_size(self):
        # the size if estimated at bits, we transform it into bytes
        return int(self.context.get_allocated_size()/8)
    
    def add_clean_up(self, clean_up_sec) -> 'Driver':
        self.clean_up_sec = clean_up_sec
        return self