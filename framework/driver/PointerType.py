from . import Type

class PointerType(Type):
    def __init__(self, token, type: Type):
        super().__init__(token)
        self.type = type

    def get_pointee_type(self):
        return self.type