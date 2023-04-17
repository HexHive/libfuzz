from driver.ir.java.type import JavaType


class Variable:
    def __init__(self, type: JavaType, token: str):
        self.type = type
        self.token = token # This is the name of this variable