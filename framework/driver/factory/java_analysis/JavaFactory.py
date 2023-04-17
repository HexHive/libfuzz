from abc import ABC

from typing import Dict, List, Set

from driver import Driver
from common import JavaApi, JavaArg
from driver.ir import Statement
from driver.ir.java.statement import *
from driver.ir.java.type import *

class JavaFactory(ABC):

    def __init__(self, api_list: List[JavaApi], subtypes: Dict[str, Set[str]]):
        self.api_list = api_list
        self.subtypes = subtypes

    def create_random_driver(self) -> Driver:
        pass

    def api_to_apicall(self, api: JavaApi) -> Statement:
        if api.is_public():
            if api.is_constructor:
                return self.api_to_classcreate(api)
            return self.api_to_apiinvoke(api)
        # I guess we should ignore non-public API

    def api_to_classcreate(self, api: JavaApi) -> ClassCreate:
        arguments_info = api.arguments_info

        arg_list_type = []
        for arg in arguments_info:
            the_type = self.normalize_type(arg)
            arg_list_type += [the_type]

        return ClassCreate(self.normalize_type(api.declaring_class), arg_list_type)

    def api_to_apiinvoke(self, api: JavaApi) -> ApiInvoke:
        function_name = api.function_name
        arguments_info = api.arguments_info

        arg_list_type = []
        for arg in arguments_info:
            the_type = self.normalize_type(arg)
            arg_list_type += [the_type]

        return ApiInvoke(function_name, self.normalize_type(api.declaring_class), self.normalize_type(api.return_info), arg_list_type, api.is_static())

    def normalize_type(self, arg: JavaArg) -> JavaType:
        if arg.argType:
            return ParameterizedType(arg.rawType, arg.argType, self.subtypes)
        if arg.rawType.startswith("["):
            return ArrayType(arg.rawType, self.subtypes)
        return ClassType(arg.rawType, self.subtypes, arg.is_primitive())
