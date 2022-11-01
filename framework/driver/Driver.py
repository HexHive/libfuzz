from typing import List, Set, Dict, Tuple, Optional
from .ir import Statement

class Driver:
    statements: List[Statement]

    def __init__(self, statements, context):
        self.statements = statements
        self.context = context

    def __iter__(self):
        for s in self.statements:
            yield s
 
    def get_input_size(self):
        # the size if estimated at bits, we transform it into bytes
        return int(self.context.get_allocated_size()/8)