import ast
from typing import Dict, List, Set, Tuple

from driver import Driver
from common import JavaApi, JavaArg
from driver.ir.java.statement import ClassCreate, MethodCall, ApiInvoke
from driver.ir.java.type import *

class JavaFactory:

    # api_list is the api for testing, full_api_list is the whole api in the library
    def __init__(self, api_list: Tuple[Set[JavaApi], Set[JavaApi]], subtypes: Dict[Tuple[str, str], Set[str]]):
        self.full_api_list, self.api_list = api_list
        self.subtypes = subtypes

    def create_random_driver(self) -> Driver:
        from driver import JavaContext

        api_stmts = [JavaFactory.api_to_apicall(api, self.subtypes) for api in self.api_list]
        
        ctx = JavaContext(self.subtypes, self.full_api_list)

        stmts = []
        for stmt in api_stmts:
            stmts += ctx.complete_statement(stmt)
            #print(stmts)
        return Driver(stmts, ctx)      

    @staticmethod
    def api_to_apicall(api: JavaApi, subtypes: Dict[Tuple[str, str], Set[str]]) -> MethodCall:
        if api.is_public():
            if api.is_constructor:
                return JavaFactory.api_to_classcreate(api, subtypes)
            return JavaFactory.api_to_apiinvoke(api, subtypes)
        # I guess we should ignore non-public API

    @staticmethod
    def api_to_classcreate(api: JavaApi, subtypes: Dict[Tuple[str, str], Set[str]]) -> ClassCreate:
        arguments_info = api.arguments_info

        arg_list_type = []
        for arg in arguments_info:
            the_type = JavaFactory.normalize_type(arg, subtypes)
            arg_list_type += [the_type]

        exception_list_type = []
        for exception in api.exceptions:
            the_type = JavaFactory.normalize_type(exception, subtypes)
            exception_list_type += [the_type]

        return ClassCreate(JavaFactory.normalize_type(api.declaring_class, subtypes), arg_list_type, JavaFactory.filter_exceptions(exception_list_type, subtypes))

    @staticmethod
    def api_to_apiinvoke(api: JavaApi, subtypes: Dict[Tuple[str, str], Set[str]]) -> ApiInvoke:
        function_name = api.function_name
        arguments_info = api.arguments_info

        arg_list_type = []
        for arg in arguments_info:
            the_type = JavaFactory.normalize_type(arg, subtypes)
            arg_list_type += [the_type]

        exception_list_type = []
        for exception in api.exceptions:
            the_type = JavaFactory.normalize_type(exception, subtypes)
            exception_list_type += [the_type]

        return ApiInvoke(function_name, JavaFactory.normalize_type(api.declaring_class, subtypes), JavaFactory.normalize_type(api.return_info, subtypes), arg_list_type, JavaFactory.filter_exceptions(exception_list_type, subtypes), api.is_static())

    @staticmethod
    def normalize_type(arg: JavaArg, subtypes: Dict[Tuple[str, str], Set[str]]) -> JavaType:
        if arg.argType:
            return ParameterizedType(arg.rawType, arg.argType, subtypes)
        if arg.rawType.startswith("["):
            return ArrayType(arg.rawType, subtypes)
        return ClassType(arg.rawType, subtypes, arg.is_primitive())
    
    @staticmethod
    def normalize_type_str(type_str: Tuple[str, str], subtypes: Dict[Tuple[str, str], Set[str]]) -> JavaType:
        rawType = type_str[0]
        argType = ast.literal_eval(type_str[1])
        if argType:
            return ParameterizedType(rawType, argType, subtypes)
        if rawType.startswith("["):
            return ArrayType(rawType, subtypes)
        return ClassType(rawType, subtypes, not "." in rawType)
    
    @staticmethod
    def filter_exceptions(exceptions: List[JavaType], subtypes: Dict[Tuple[str, str], Set[str]]) -> List[JavaType]:
        all_exceptions = set()
        filtered_exceptions = []
        for exc in exceptions:
            assert isinstance(exc, ClassType)
            if exc.className in all_exceptions:
                continue
            filtered_exceptions.append(exc)
            all_exceptions.update(subtypes.get((exc.className, str([])), set()))
        return filtered_exceptions