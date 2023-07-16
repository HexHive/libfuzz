import random
from typing import Dict, List
import os
from backend import BackendDriver
from driver import Driver
from driver.ir.java.statement import ClassCreate, ApiInvoke, ArrayCreate, MethodCall
from driver.ir.java.type import ClassType, ArrayType, ParameterizedType, JavaType
from driver.ir.java.variable import Variable

class JavaBackendDriver(BackendDriver):
    def __init__(self, working_dir, seeds_dir, num_seeds):
        self.working_dir = working_dir
        self.seeds_dir = seeds_dir
        self.num_seeds = num_seeds

        self._idx = 1
        self.builtin_set = set((
            "java.util.List",
            "java.lang.String",
            "java.lang.CharSequence",
            "java.io.InputStream",
            "java.awt.image.BufferedImage",
            "java.io.Reader"
        ))
        self.builtin_dict_normal: Dict[str, List[str]] = {
            "java.lang.String": ["String %s = data.consumeString(100);"],
            "java.lang.CharSequence": ["String %s = data.consumeString(100);"],
            "java.io.InputStream": ["java.io.InputStream %s = new java.io.ByteArrayInputStream(data.consumeBytes(100));"],
            "java.awt.image.BufferedImage": ["java.awt.image.BufferedImage %s = javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(data.consumeBytes(10000)));"],
            "java.io.Reader": ["java.io.ByteArrayInputStream inStream = new java.io.ByteArrayInputStream(data.consumeBytes(100));\n    java.io.InputStreamReader %s = new java.io.InputStreamReader(inStream);"]
        }
        self.builtin_dict_last: Dict[str, List[str]] = {
            "java.lang.String": ["String %s = data.consumeRemainingAsString();"],
            "java.lang.CharSequence": ["String %s = data.consumeRemainingAsString();"],
            "java.io.InputStream": ["java.io.InputStream %s = new java.io.ByteArrayInputStream(data.consumeRemainingAsBytes());"],
            "java.awt.image.BufferedImage": ["java.awt.image.BufferedImage %s = javax.imageio.ImageIO.read(new java.io.ByteArrayInputStream(data.consumeRemainingAsBytes()));"],
            "java.io.Reader": ["java.io.ByteArrayInputStream inStream = new java.io.ByteArrayInputStream(data.consumeRemainingAsBytes());\n    java.io.Reader %s = new java.io.InputStreamReader(inStream);"]
        }
        self.builtin_generic_dict = {
            "java.util.List": ["java.util.List %s = new java.util.ArrayList<>();"]
        }
        self.jazzer_base_dict = {
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

        self.var_dict: Dict[MethodCall, Variable] = {}
        self.builtin_stmts: List[MethodCall] = []

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
            
        fuzz_input = self.__emit_fuzz_input()
            
        #print(driver_content)
        with open(os.path.join(self.working_dir, driver_filename), "w") as f:
            f.write(header)
            f.write(fuzz_input)
            f.write(driver_content)
            f.write(ending)
        
        self.__clear()

    def emit_seeds(self, driver, driver_filename):
        pass

    def __clear(self):
        self.var_dict = {}
        self.builtin_stmts = []

    def emit_methodcall(self, stmt: MethodCall) -> str:
        if isinstance(stmt, ArrayCreate):
            return self.emit_arraycreate(stmt)
        
        if isinstance(stmt, ClassCreate):
            return self.emit_classcreate(stmt)
        elif isinstance(stmt, ApiInvoke):
            return self.emit_apiinvoke(stmt)
        else:
            raise Exception("Unsupported Statement")
        
        if not stmt.exceptions:
            if JavaBackendDriver.void_return(stmt):
                return content
            return f"{typename} {content}"
        if JavaBackendDriver.void_return(stmt):
            stmt_header = "\n"
        else:
            stmt_header = f"{typename} {token};\n"
        return f"{stmt_header}" \
               "    try {\n" \
               f"      {content}\n" \
               "    } catch (" + "| ".join([x.className for x in stmt.exceptions]) + " e) {\n" \
               "      return;\n" \
               "    }"

    def emit_classcreate(self, stmt: ClassCreate) -> str:
        declaring_class = stmt.declaring_class
        if isinstance(declaring_class, ArrayType):
            raise Exception("ArrayType should use ArrayCreate")
        
        token = self.__assign_token(stmt)

        if isinstance(declaring_class, ClassType):
            if declaring_class.is_primitive:
                self.builtin_stmts.insert(0, stmt)
                return ""
            elif declaring_class.className in self.builtin_set:
                self.builtin_stmts.append(stmt)
                return ""
                type_dict = {**self.jazzer_addition_dict, **self.jazzer_base_dict}
                return f"{stmt.class_var.token} = data.{type_dict[declaring_class.className]}();", declaring_class.className, stmt.class_var.token
            typeName = JavaBackendDriver.normalize_className(declaring_class.className)
            return self.assign_token_to_stmt(typeName, token, f"new {typeName}", stmt.arg_stmts, stmt.exceptions)
        elif isinstance(declaring_class, ParameterizedType):
            if declaring_class.rawType.className in self.builtin_set:
                self.builtin_stmts.append(stmt)
                return ""
                return f"{token} = new {self.builtin_dict[declaring_class.rawType.className]}<>();", JavaBackendDriver.normalize_typeName(declaring_class), token
            else:
                raise Exception("Not Support ParameterizedType Creation")

    def emit_arraycreate(self, stmt: ArrayCreate) -> str:
        declaring_class = stmt.declaring_class

        assert isinstance(declaring_class, ArrayType)

        token = self.__assign_token(stmt)

        if declaring_class.rawType.is_primitive and declaring_class.dimension == 1:
            if declaring_class.rawType.className == "byte":
                self.builtin_stmts.append(stmt)
                return ""
            self.builtin_stmts.insert(0, stmt)
            return ""
            # handle array data which can be directly provided by fuzzedData
            if declaring_class.rawType.className in self.jazzer_base_dict:
                return f"{declaring_class.rawType.className}[] {token} = data.{self.jazzer_base_dict[declaring_class.rawType.className]}s({stmt.init_len});"
            elif declaring_class.rawType.className in self.jazzer_addition_dict:
                return f"{declaring_class.rawType.className}[] {token} = new {declaring_class.rawType.className}[data.consumeInt(1, 100)];\n" + f"    for (int i = 0; i < {token}.length; ++i) " + "{\n      " + f"{token}[i] = data.{self.jazzer_addition_dict[declaring_class.rawType.className]}();\n" + "    }"
            else:
                raise Exception("Unsupported primitive type")
        else:
            return JavaBackendDriver.normalize_className(declaring_class.rawType.className) + "[]" * declaring_class.dimension + f" {token} = new {JavaBackendDriver.normalize_className(declaring_class.rawType.className)}[{stmt.init_len}]" + "[]" * (declaring_class.dimension - 1) + ";"

    def emit_apiinvoke(self, stmt: ApiInvoke) -> str:
        token = self.__assign_token(stmt)

        assert isinstance(stmt.declaring_class, ClassType)

        className = JavaBackendDriver.normalize_className(stmt.declaring_class.className)
        typeName = JavaBackendDriver.normalize_typeName(stmt.ret_type)

        if stmt.is_static:
            return self.assign_token_to_stmt(typeName, token, f"{className}.{stmt.function_name}", stmt.arg_stmts, stmt.exceptions)
        return self.assign_token_to_stmt(typeName, token, f"{self.var_dict[stmt.class_stmt].token}.{stmt.function_name}", stmt.arg_stmts, stmt.exceptions)
    
    def __assign_token(self, stmt: MethodCall) -> str:
        var = Variable(stmt.ret_type)
        self.var_dict[stmt] = var
        return var.token
    
    def __emit_fuzz_input(self) -> str:
        if not self.builtin_stmts:
            return ""
        result = ""
        last_stmt = self.builtin_stmts.pop()
        for stmt in self.builtin_stmts:
            result += f"    {self.__emit_builtin_stmt(stmt, False)}\n"
        result += f"    {self.__emit_builtin_stmt(last_stmt, True)}\n"
        return result
        
    def __emit_builtin_stmt(self, stmt: MethodCall, last_stmt: bool) -> str:
        token = self.var_dict[stmt].token

        if isinstance(stmt, ClassCreate):
            if isinstance(stmt.declaring_class, ClassType):

                className = stmt.declaring_class.className
                jazzer_dict = self.jazzer_addition_dict | self.jazzer_base_dict

                if className in self.builtin_dict_normal:
                    if last_stmt:
                        template = random.choice(self.builtin_dict_last[stmt.declaring_class.className])
                        return template % token
                    else:
                        template = random.choice(self.builtin_dict_normal[stmt.declaring_class.className])
                        print(template)
                        return template % token
                elif className in jazzer_dict:
                    return f"{className} {token} = data.{jazzer_dict[className]}();"
            elif isinstance(stmt.declaring_class, ParameterizedType):
                return random.choice(self.builtin_generic_dict[stmt.declaring_class.rawType.className]) % token
        elif isinstance(stmt, ArrayCreate):
            declaring_class = stmt.declaring_class

            assert isinstance(declaring_class, ArrayType)
            assert declaring_class.dimension == 1

            className = declaring_class.rawType.className

            if className == "byte":
                if last_stmt:
                    return f"byte[] {token} = data.consumeRemainingAsBytes();"
                else:
                    return f"byte[] {token} = data.consumeBytes({stmt.init_len});"
            elif className in self.jazzer_base_dict:
                return f"{className}[] {token} = data.{self.jazzer_base_dict[className]}s({stmt.init_len});"
            elif className in self.jazzer_addition_dict:
                return f"{className}[] {token} = new {className}[data.consumeInt(1, 100)];\n" + f"    for (int i = 0; i < {token}.length; ++i) " + "{\n      " + f"{token}[i] = data.{self.jazzer_addition_dict[className]}();\n" + "    }"
        

    @staticmethod
    def normalize_className(className: str):
        if className.startswith("."):
            return className[1:]
        return className
    
    @staticmethod
    def normalize_typeName(type: JavaType):
        if isinstance(type, ClassType):
            return JavaBackendDriver.normalize_className(type.className)
        if isinstance(type, ParameterizedType):
            return f"{type.rawType.className}<" + ", ".join([x.className for x in type.argType]) + ">"
        if isinstance(type, ArrayType):
            return type.rawType.className + type.dimension * "[]"
        raise Exception("Not Supported Type")
    
    @staticmethod
    def is_void(type: JavaType):
        if isinstance(type, ClassType):
            if type.is_primitive and type.className == "void":
                return True
        return False
    
    def assign_token_to_stmt(self, typeName: str, token: str, sentence: str, args: List[MethodCall], exceptions: List[JavaType]) -> str:
        arg_str = "(" + ", ".join([self.var_dict[arg].token for arg in args]) + ");"
        content = sentence + arg_str
        if typeName == "void":
            return JavaBackendDriver.wrap_with_try_catch(content, exceptions)
        first_line = f"{typeName} {token};\n"
        second_line = JavaBackendDriver.wrap_with_try_catch(f"{token} = " + content, exceptions)
        return first_line + "    " + second_line

    @staticmethod
    def wrap_with_try_catch(content: str, exceptions: List[ClassType]) -> str:
        if not exceptions:
            return content
        result = "try {\n" \
               f"      {content}\n" \
               "    } "
        for x in exceptions:
            result += f"catch ({x.className} e) " + "{\n" \
                      "      return;\n" \
                      "    } "
        return result