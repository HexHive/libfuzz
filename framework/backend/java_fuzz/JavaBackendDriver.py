import os
from backend import BackendDriver
from driver import Driver
from driver.ir.java.statement import ClassCreate, ApiInvoke, ArrayCreate, MethodCall
from driver.ir.java.type import ClassType, ArrayType, ParameterizedType

class JavaBackendDriver(BackendDriver):
    def __init__(self, working_dir, seeds_dir, num_seeds):
        self.working_dir = working_dir
        self.seeds_dir = seeds_dir
        self.num_seeds = num_seeds

        self._idx = 0
        self.builtin_dict = {
            "java.util.List": "java.util.ArrayList"
        }
        self.jazzer_base_dict = {
            "byte": "consumeByte",
            "boolean": "consumeBoolean",
            "short": "consumeShort",
            "int": "consumeInt",
            "long": "consumeLong"
        }
        # This is used to handle type that does not have a array format
        self.jazzer_addition_dict = {
            "float": "consumeFloat",
            "double": "consumeDouble",
            "char": "consumeChar"
        }

    def get_name(self) -> str:
        m_idx = self._idx 
        self._idx = self._idx + 1

        file_name = f"Driver{m_idx}.java"

        return file_name
    
    def emit_driver(self, driver: Driver, driver_filename: str):
        header = "import com.code_intelligence.jazzer.api.FuzzedDataProvider;\n\n"
        header += "public class " + driver_filename[:-5] + " {\n"
        header += "  public static void fuzzerTestOneInput(FuzzedDataProvider data) {\n"

        ending = "  }\n"
        ending += "}"

        driver_content = ""
        for stmt in driver:
            if isinstance(stmt, MethodCall):
                driver_content += "    " + self.emit_methodcall(stmt) + "\n"
            else:
                raise Exception("Unsupported Statement")
            
        print(driver_content)
        with open(os.path.join(self.working_dir, driver_filename), "w") as f:
            f.write(header)
            f.write(driver_content)
            f.write(ending)

    def emit_seeds(self, driver, driver_filename):
        pass

    def emit_methodcall(self, stmt: MethodCall) -> str:
        if isinstance(stmt, ArrayCreate):
            return self.emit_arraycreate(stmt)
        
        if isinstance(stmt, ClassCreate):
            content = self.emit_classcreate(stmt)
        elif isinstance(stmt, ApiInvoke):
            content = self.emit_apiinvoke(stmt)
        else:
            raise Exception("Unsupported Statement")
        
        if not stmt.exceptions:
            return content
        return "try {\n" \
               f"      {content}\n" \
               "    } catch (" + "| ".join([x.className for x in stmt.exceptions]) + " e ) {\n" \
               "      return;\n" \
               "    }"

    def emit_classcreate(self, stmt: ClassCreate) -> str:
        declaring_class = stmt.declaring_class
        if isinstance(declaring_class, ArrayType):
            raise Exception("ArrayType should use ArrayCreate")
        
        if isinstance(declaring_class, ClassType):
            if declaring_class.is_primitive:
                type_dict = self.jazzer_addition_dict | self.jazzer_base_dict
                return f"{declaring_class.className} {stmt.class_var.token} = data.{type_dict[declaring_class.className]}();"
            elif declaring_class.className == "java.lang.String":
                # This one is a little bit tricky
                return f"String {stmt.class_var.token} = data.consumeString(100);"
            return f"{JavaBackendDriver.normalize_className(declaring_class.className)} {stmt.class_var.token} = new {JavaBackendDriver.normalize_className(declaring_class.className)}(" + ", ".join([var.token for var in stmt.arg_vars]) + ");"
        elif isinstance(declaring_class, ParameterizedType):
            if declaring_class.rawType.className in self.builtin_dict:
                return f"{declaring_class.rawType.className}<" + ", ".join([x.className for x in declaring_class.argType]) + f"> {stmt.class_var.token} = new {self.builtin_dict[declaring_class.rawType.className]}<>();"
            else:
                raise Exception("Not Support ParameterizedType Creation")

    def emit_arraycreate(self, stmt: ArrayCreate) -> str:
        declaring_class = stmt.declaring_class
        if declaring_class.rawType.is_primitive and declaring_class.dimension == 1:
            # handle array data which can be directly provided by fuzzedData
            if declaring_class.rawType.className in self.jazzer_base_dict:
                return f"{declaring_class.rawType.className}[] {stmt.class_var.token} = data.{self.jazzer_base_dict[declaring_class.rawType.className]}s({stmt.init_len});"
            elif declaring_class.rawType.className in self.jazzer_addition_dict:
                return f"{declaring_class.rawType.className}[] {stmt.class_var.token} = new {declaring_class.rawType.className}[data.consumeInt(1, 100)];\n" + f"    for (int i = 0; i < {stmt.class_var.token}.length; ++i) " + "{\n      " + f"{stmt.class_var.token}[i] = data.{self.jazzer_addition_dict[declaring_class.rawType.className]}();\n" + "    }"
            else:
                raise Exception("Unsupported primitive type")
        else:
            return JavaBackendDriver.normalize_className(declaring_class.rawType.className) + "[]" * declaring_class.dimension + f" {stmt.class_var} = new {JavaBackendDriver.normalize_className(declaring_class.rawType.className)}[{stmt.init_len}]" + "[]" * (declaring_class.dimension - 1) + ";"

    def emit_apiinvoke(self, stmt: ApiInvoke) -> str:
        if stmt.is_static:
            return f"var {stmt.ret_var.token} = {JavaBackendDriver.normalize_className(stmt.declaring_class.className)}.{stmt.function_name}(" + ", ".join([var.token for var in stmt.arg_vars])  + ");"
        return f"var {stmt.ret_var.token} = {stmt.class_var.token}.{stmt.function_name}(" + ", ".join([var.token for var in stmt.arg_vars])  + ");"
    
    @staticmethod
    def normalize_className(className: str):
        if className.startswith("."):
            return className[1:]
        return className