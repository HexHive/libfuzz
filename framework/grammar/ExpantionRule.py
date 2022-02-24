class ExpantionRule:
    def __init__(self, elements):
        self.new_elements = elements

    def __str__(self):
        return ";".join([str(e) for e in self.new_elements])