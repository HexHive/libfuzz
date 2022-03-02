from driver import Driver, ApiCall, VarDecl, Type, PointerType, Address, Variable, Statement, Value
from miner import BackendDriver

import random, string, os

class MockBackendDriver(BackendDriver):

    def __init__(self, working_dir):
        self.working_dir = working_dir

    # this return the filename
    def emit(self, driver: Driver) -> str:

        print(self.working_dir)

        # file name for the driver
        driver_filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10)) + ".txt"

        print(f"Driver filename: {driver_filename}")

        stmt_instances = []

        for stmt in driver:
            stmt_instances.append(self.stmt_emit(stmt))

        with open(os.path.join(self.working_dir, driver_filename), "w") as f:
            for stmt in stmt_instances:
                f.write(stmt + "\n")

        print(driver.get_input_size())

        return driver_filename


    # # PointerType
    # def emit_code(self):
    #     var = self.variable
    #     type = var.get_type()
    #     return f"[THIS IS A POINTER!] {type.emit_code()} {var.get_token()} = input();"

    # Address
    def address_emit(self, address: Address):
        variable = address.variable
        return f"&{self.variable_emit(variable)}"

    def stmt_emit(self, stmt: Statement):
        if isinstance(stmt, VarDecl):
            return self.vardec_emit(stmt)
        elif isinstance(stmt, ApiCall):
            return self.apicall_emit(stmt)
        raise NotImplementedError

    # VarDecl
    def vardec_emit(self, vardecl: VarDecl):
        var = vardecl.variable
        type = var.get_type()

        return f"{self.type_emit(type)} {self.variable_emit(var)} = input();"

    # ApiCall
    def apicall_emit(self, apicall: ApiCall):
        ret_var = apicall.ret_var
        arg_vars = apicall.arg_vars
        function_name = apicall.function_name

        ret_var_code = self.value_emit(ret_var)
        arg_vars_code = ", ".join([self.value_emit(a) for a in arg_vars])

        if ret_var.get_type() == Type("void"):
            return f"{function_name}({arg_vars_code});"

        return f"{ret_var_code} = {function_name}({arg_vars_code});"
    
    # Value
    def value_emit(self, value: Value) -> str:
        if isinstance(value, Variable):
            return self.variable_emit(value)
        if isinstance(value, Address):
            return self.address_emit(value)

        raise Exception(f"I don't know {value}")

    # Variable
    def variable_emit(self, variable: Variable) -> str:
        var_str = variable.token.replace("%", "")

        if "." in var_str:
            var_str = var_str.split(".")[-1]

        return var_str

    # Type
    def type_emit(self, type: Type) -> str:
        var_str = type.token.replace("%", "")

        if "." in var_str:
            var_str = var_str.split(".")[-1]

        return var_str