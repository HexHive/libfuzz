from driver import Driver
from miner import BackendDriver

class MockBackendDriver(BackendDriver):

    def __init__(self):
        pass

    def emit(self, driver: Driver) -> str:
        print(driver)
        print("TODO: how to emit this shit? into another object container?")
        return driver


    # # PointerType
    # def emit_code(self):
    #     var = self.variable
    #     type = var.get_type()
    #     return f"[THIS IS A POINTER!] {type.emit_code()} {var.get_token()} = input();"

    # # Address
    # def emit_code(self):
    #     var_str = self.variable
    #     return f"&{var_str.emit_code()}"

    # # VarDecl
    # def emit_code(self):
    #     var = self.variable
    #     type = var.get_type()
    #     return f"{type.emit_code()} {var.emit_code()} = input();"

    # # ApiCall
    # def emit_code(self):
    #     ret_var = self.ret_var
    #     arg_vars = self.arg_vars
    #     function_name = self.function_name

    #     ret_var_code = ret_var.emit_code()
    #     arg_vars_code = ", ".join([a.emit_code() for a in arg_vars])

    #     if ret_var.get_type() == Type("void"):
    #         return f"{function_name}({arg_vars_code});"

    #     return f"{ret_var_code} = {function_name}({arg_vars_code});"
    
    # # Variable
    # def emit_code(self):
    #     var_str = self.token.replace("%", "")

    #     if "." in var_str:
    #         var_str = var_str.split(".")[-1]

    #     return var_str



    # # Type
    # def emit_code(self):

    #     var_str = self.token.replace("%", "")

    #     if "." in var_str:
    #         var_str = var_str.split(".")[-1]

    #     return var_str

        # return self.token