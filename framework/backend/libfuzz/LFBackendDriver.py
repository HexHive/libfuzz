from driver import Driver
from driver.ir import ApiCall, BuffDecl, BuffInit, Type, PointerType, Address, Variable, Statement, Value, NullConstant
from backend import BackendDriver

import random, string, os, shutil

class LFBackendDriver(BackendDriver):

    def __init__(self, working_dir, seeds_dir, num_seeds, headers_dir):
        self.working_dir = working_dir
        self.seeds_dir   = seeds_dir
        self.headers_dir = headers_dir
        self.num_seeds = num_seeds
        self._idx = 0

        self.headers = [] # os.listdir(headers_dir)
        for root, _, f_names in os.walk(headers_dir):
            for f in f_names:
                if f.endswith(".h") or f.endswith(".hpp") or f.endswith(".hxx"):
                    f_full = os.path.join(root, f)
                    f_rel = os.path.relpath(f_full, headers_dir)
                    self.headers.append(f_rel)

    def get_name(self) -> str:
        m_idx = self._idx 
        self._idx = self._idx + 1

        file_name = f"driver{m_idx}.cc"

        return file_name

    def emit_seeds(self, driver, driver_filename: str):

        # hack to remove extension!
        if "." in driver_filename:
            ext_pos = driver_filename.find(".")
            driver_filename = driver_filename[:ext_pos]

        seed_folder = os.path.join(self.seeds_dir, driver_filename)

        # clean previous seeds
        shutil.rmtree(seed_folder, ignore_errors=True)
        os.mkdir(seed_folder)

        # seed size in bytes
        seed_size = driver.get_input_size()
        
        for x in range(1, self.num_seeds + 1):
            with open(os.path.join(seed_folder, f"seed{x}.bin"), "wb") as f:
                f.write(os.urandom(seed_size))

    # this return the filename
    def emit_driver(self, driver: Driver, driver_filename: str):

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

            f.write(f"\n#include <string.h>\n")

            f.write("\n")

            f.write("extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t Size) {\n")

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
        elif isinstance(stmt, BuffInit):
            return self.buffinit_emit(stmt)
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

        const_attr = "const " if type.is_const else ""

        return f"{const_attr}{self.type_emit(type)} {str_stars}{token}[{n_element}];"

    # BuffInit
    def buffinit_emit(self, buffinit: BuffInit) -> str:
        buffer      = buffinit.get_buffer()

        type        = buffer.get_type()
        token       = self.clean_token(buffer.get_token())

        if type.is_incomplete:
            raise Exception(f"I can't initialize a buffer of imcomplete types {type}")
  
        return f"memcpy({token}, data, sizeof({token}));data += sizeof({token});"

    # ApiCall
    def apicall_emit(self, apicall: ApiCall) -> str:
        ret_var = apicall.ret_var
        ret_type = apicall.ret_type
        arg_vars = apicall.arg_vars
        function_name = apicall.function_name

        ret_var_code = self.value_emit(ret_var)
        arg_vars_code = ", ".join([self.value_emit(a) for a in arg_vars])

        if isinstance(ret_var, Address):
            ret_var_type = ret_var.get_variable().get_type()
        elif isinstance(ret_var, NullConstant):
            ret_var_type = ret_var.type
        else:
            ret_var_type = ret_var.get_type()

        if ret_var_type == Type("void"):
            return f"{function_name}({arg_vars_code});"

        # if self.function_name == "_TIFFmalloc":
        #     from IPython import embed; embed(); exit()

        cast_operator = ""

        if ret_type != ret_var_type:
            # type_emit = self.type_emit(ret_var_type)
            # from IPython import embed; embed(); exit()
            # type_emit = self.clean_token()
            cast_operator = f"({ret_var_type.token})"

        return f"{ret_var_code} = {cast_operator} {function_name}({arg_vars_code});"
    
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