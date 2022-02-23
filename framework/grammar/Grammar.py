from abc import ABC, abstractmethod

from . import Element, NonTerminal, ExpantionRule

class Grammar(ABC):
    def __init__(self, start_term: NonTerminal):
        self.elements = {}
        self.elements[start_term] = set()
        self.start_term = start_term
    
    def add_expantion_rule(self, elem_nt: NonTerminal, exprule: ExpantionRule):
        if elem_nt not in self.elements:
            self.elements[elem_nt] = set()
        self.elements[elem_nt].add(exprule)

    def get_expansion_rules(self, elem: NonTerminal):
        if not elem in self.elements:
            raise Exception(f"Element {elem} not in the grammar")

        return self.elements[elem]

    def num_expansions(self):
        return len(self.expansion_list)

    def __iter__(self):
        for v in self.elements:
            yield v

    def num_elements(self):
        return len(self.elements)

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.start_term.name}, n_elem={self.num_elements()})"
    
