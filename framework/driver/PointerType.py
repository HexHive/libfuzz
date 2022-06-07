from . import Type

class PointerType(Type):
    def __init__(self, token, type: Type):
        super().__init__(token)
        self.type = type

    def get_pointee_type(self):
        return self.type

    def get_base_type(self):
        parent_type = self.get_pointee_type()

        if not isinstance(parent_type, PointerType):
            return parent_type

        return parent_type.get_base_type()