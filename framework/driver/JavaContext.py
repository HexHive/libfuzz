import random
from typing import Dict, List, Set, Tuple


from common.javaapi import JavaApi
from .ir import Statement
from .ir.java.type import *
from .ir.java.variable import Variable
from .ir.java.statement import *
from .factory.java_analysis import JavaFactory

class JavaContext:
    type_map = {}

    def __init__(self, subtypes: Dict[Tuple[str, str], Set[str]], full_api_list: Set[JavaApi], prob_gen=0.2) -> None:
        self.variable_alive: Dict[JavaType, Set[Variable]] = {}
        self.prob_gen = prob_gen # This is the probability of generating new variable when we already have this type of variable
        self.initial_stmts: List[Statement] = [] # This records the statements used to generate new variable
        self.subtypes = subtypes

        constructors, methods = self.filter_by_constructor(full_api_list)
        self.constructor_dict = self.generate_constructor_dict(constructors)
        self.ret_dict = self.generate_return_dict(methods)

        self.builtin_set = set(("java.util.Map", "java.util.List"))
    
    def fulfill_statement(self, stmt: MethodCall):
        for pos, arg_type in stmt.get_pos_args_types():
            arg_var = self.get_random_var(arg_type)
            self.add_var(arg_var)
            stmt.set_pos_arg_var(pos, arg_var)
                
        if isinstance(stmt, ApiInvoke):
            if not stmt.is_static:
                class_var = self.get_random_var(stmt.declaring_class)
                self.add_var(class_var)
                stmt.set_class_var(class_var)
            ret_var = Variable(stmt.return_type)
            stmt.set_ret_var(ret_var)
            self.add_var(ret_var)
        elif isinstance(stmt, ClassCreate):
            class_var = Variable(stmt.declaring_class)
            self.add_var(class_var)
            stmt.set_class_var(class_var)
    
    def get_random_var(self, type: JavaType) -> Variable:
        if type in self.variable_alive and random.random() > self.prob_gen:
                variable_list = self.variable_alive[type]
                return random.choice(list(variable_list))
        else:
            if type in self.ret_dict and random.randint(0, 1) == 0:
                # get variable from return value
                apis = self.ret_dict[type]
                api = JavaContext.select_api(apis)
                stmt = JavaFactory.api_to_apiinvoke(api, self.subtypes)
                self.fulfill_statement(stmt)
                self.initial_stmts.append(stmt)
                return stmt.ret_var
            else:
                # construct a new object
                if self.is_builtin(type):
                    var = Variable(type)
                    stmt = ClassCreate(type, [], [])
                    stmt.set_class_var(var)
                    self.initial_stmts.append(stmt)
                    self.add_var(var)
                    return var
                else:
                    if isinstance(type, ArrayType):
                        stmt = ArrayCreate(type)
                        var = Variable(type)
                        stmt.set_class_var(var)
                        self.initial_stmts.append(stmt)
                        self.add_var(var)
                        return var
                    
                    if not type in self.constructor_dict:
                        raise Exception(f"Unsupported Type: {type}")
                    
                    apis = self.constructor_dict[type]
                    api = JavaContext.select_api(apis)
                    stmt = JavaFactory.api_to_classcreate(api, self.subtypes)
                    self.fulfill_statement(stmt)
                    self.initial_stmts.append(stmt)
                    return stmt.class_var
    
    def add_var(self, var: Variable):
        type = var.type
        if not type in self.variable_alive:
            self.variable_alive[type] = set()
        var_set = self.variable_alive[type]
        var_set.add(var)

    def generate_initialization_statements(self) -> List[Statement]:
        return self.initial_stmts
        
    def filter_by_constructor(self, full_api_list: Set[JavaApi]) -> Tuple[List[JavaApi], List[JavaApi]]:
        constructors, methods = [], []
        for api in full_api_list:
            if api.is_constructor:
                constructors.append(api)
            else:
                methods.append(api)
        return constructors, methods

    def generate_constructor_dict(self, constructors: List[JavaApi]) -> Dict[JavaType, List[JavaApi]]:
        constructor_dict: Dict[str, List[JavaApi]] = {}
        for constructor in constructors:
            declaring_clazz = constructor.declaring_class
            # constructor is not possible to have argType
            key = declaring_clazz.rawType
            if not key in constructor_dict:
                constructor_dict[key] = []
            constructor_dict[key].append(constructor)
        
        types = set(constructor_dict.keys())
        for rawType, argTypes in self.subtypes:
            if argTypes == str([]):
                types.add(rawType)

        result: Dict[JavaType, List[JavaApi]] = {}
        for key in types:
            constructor_list = constructor_dict.get(key, [])

            for item in self.subtypes.get((key, str([])), set()):
                constructor_list += constructor_dict.get(item, [])
            
            if constructor_list:
                result[ClassType(key, self.subtypes, False)] = constructor_list
        
        return result

    def generate_return_dict(self, methods: List[JavaApi]) -> Dict[JavaType, List[JavaApi]]:
        method_dict: Dict[Tuple[str, str], List[JavaApi]] = {}
        for method in methods:
            ret_type = method.return_info
            key = ret_type.rawType, str(ret_type.argType)
            if not key in method_dict:
                method_dict[key] = []
            method_dict[key].append(method)
        
        types = set(method_dict.keys())
        for rawType, argTypes in self.subtypes:
            if argTypes == str([]):
                types.add(rawType)
        
        result: Dict[JavaType, List[JavaApi]] = {}
        for key in method_dict:
            method_list = method_dict.get(key, [])

            for item in self.subtypes.get(key, set()):
                method_list += method_dict.get((item, str([])), [])
            
            if method_list:
                result[JavaFactory.normalize_type_str(key, self.subtypes)] = method_list

        return result

    def is_builtin(self, type: JavaType) -> bool:
        if isinstance(type, ClassType):
            # String is a special class. We treat it as primitive
            if type.is_primitive or type.className == ("java.lang.String"):
                return True
        elif isinstance(type, ParameterizedType):
            className = type.rawType.className
            # special case for builtin type
            if className in self.builtin_set:
                return True
        return False

    @staticmethod
    def select_api(apis: List[JavaApi]) -> JavaApi:
        arg_min = 100
        for api in apis:
            if len(api.arguments_info) < arg_min:
                arg_min = len(api.arguments_info)
        
        candidates = []
        for api in apis:
            if len(api.arguments_info) == arg_min:
                candidates.append(api)

        return random.choice(candidates)
