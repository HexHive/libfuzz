from typing import List, Set, Dict, Tuple, Optional
# from . import Statement

class Driver:
    # statements: List[Statement]

    def __init__(self, statements, context):
        self.statements = statements
        self.context = context

    def __iter__(self):
        for s in self.statements:
            yield s
 
    def get_input_size(self):
        return self.context.get_allocated_size()