from . import MethodCall

# This statement is used to generate sentence such as "A a = new A(p1, p2, ...)"
# class_var in this statement represents the created instance "a"
class ClassCreate(MethodCall):
    def __hash__(self):
        return hash((self.__class__.__name__, super().__hash__()))

    def __str__(self):
        return f"{self.__class__.__name__}(name={self.declaring_class.className})"
