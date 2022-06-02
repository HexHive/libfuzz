from driver import Driver, ApiCall, BuffDecl, Type, PointerType, Address, Variable, Statement, Value, NullConstant
from miner import BackendDriver

import random, string, os

class LFBackendDriver(BackendDriver):

    def __init__(self, working_dir, headers_dir):
        self.working_dir = working_dir
        self.headers_dir = headers_dir

        self.headers = os.listdir(headers_dir)

    # this return the filename
    def emit(self, driver: Driver, driver_filename: str):

        # file name for the driver
        # driver_filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(10)) + ".txt"

        # driver_filename = "CEOBJLE6DR.txt"

        stmt_instances = []

        for stmt in driver:
            stmt_instances.append(self.stmt_emit(stmt))

        with open(os.path.join(self.working_dir, driver_filename), "w") as f:
            # TODO: add headers inclusion
            for header in self.headers:
                f.write(f"#include <{header}>\n")

            f.write("\n")

            f.write("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {\n")

            for stmt in stmt_instances:
                f.write("\t" + stmt + "\n")

            f.write("\n\treturn 0;\n}")

        # print(driver.get_input_size())

        # return driver_filename

    # Address
    def address_emit(self, address: Address) -> str:
        variable = address.variable

        if isinstance(variable.get_type(), PointerType):
            return f"{self.variable_emit(variable)}"
        else:
            return f"&{self.variable_emit(variable)}"

    def stmt_emit(self, stmt: Statement) -> str:
        if isinstance(stmt, BuffDecl):
            return self.buffdec_emit(stmt)
        elif isinstance(stmt, ApiCall):
            return self.apicall_emit(stmt)
        raise NotImplementedError

    # BuffDecl
    def buffdec_emit(self, buffdecl: BuffDecl) -> str:
        buffer      = buffdecl.get_buffer()

        type        = buffer.get_type()
        n_element   = buffer.get_number_elements()
        token       = self.clean_token(buffer.get_token())

        # if isinstance(type, PointerType):
        #     print("buffdec_emit")
        #     from IPython import embed; embed(); exit()
        
        n_stars = 0
        tmp_type = type
        while isinstance(tmp_type, PointerType):
            n_stars += 1
            tmp_type = tmp_type.get_pointee_type()

        str_stars = "*"*n_stars

        return f"{self.type_emit(type)} {str_stars}{token}[{n_element}];"

    # ApiCall
    def apicall_emit(self, apicall: ApiCall) -> str:
        ret_var = apicall.ret_var
        ret_type = apicall.ret_type
        arg_vars = apicall.arg_vars
        function_name = apicall.function_name

        ret_var_code = self.value_emit(ret_var)
        arg_vars_code = ", ".join([self.value_emit(a) for a in arg_vars])

        if ret_type == Type("void"):
            return f"{function_name}({arg_vars_code});"

        return f"{ret_var_code} = {function_name}({arg_vars_code});"
    
    # Value
    def value_emit(self, value: Value) -> str:
        if isinstance(value, Variable):
            return self.variable_emit(value)
        if isinstance(value, Address):
            return self.address_emit(value)
        if isinstance(value, NullConstant):
            return self.nullconst_emit(value)

        raise Exception(f"I don't know {value}")

    # NullConstant
    def nullconst_emit(self, nullcnst: NullConstant) -> str:
        return "NULL"

    def clean_token(self, token: str) -> str:
        t = token.replace("%", "").replace("*", "")
        if "." in t:
            t = t.split(".")[-1]
        return t

    # Variable
    def variable_emit(self, variable: Variable) -> str:
        idx     = variable.get_index()
        buffer  = variable.get_buffer()
        token   = self.clean_token(buffer.token)

        return f"{token}[{idx}]"

    # Type
    def type_emit(self, type: Type) -> str:
        if isinstance(type, PointerType):
            type = type.get_pointee_type()
        
        return self.clean_token(type.token)