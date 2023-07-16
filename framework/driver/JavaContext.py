import random
from typing import Dict, List, Optional, Set, Tuple


from common.javaapi import JavaApi
from .ir import Statement
from .ir.java.type import *
from .ir.java.statement import *
from .factory.java_analysis import JavaFactory

class Node:
    def __init__(self, stmt: MethodCall, parent: Optional['Node'], required_type: Set[JavaType]) -> None:
        self.parent = parent
        self.stmt = stmt
        self.required_type = required_type
    
    def next_type(self) -> Tuple[JavaType, 'Node']:
        next_type = self.stmt.get_next_type()
        if next_type:
            return next_type, self
        if self.parent:
            stmt = self.parent.stmt.deep_copy()
            stmt.set_next_stmt(self.stmt)
            node = Node(stmt, self.parent.parent, self.parent.required_type)
            return node.next_type()
        return None, self
    
    def set_next_stmt(self, stmt: MethodCall):
        self.stmt.set_next_stmt(stmt, True)

    def conflict(self, stmt: MethodCall):
        for type in stmt.get_all_type():
            for req_type in self.required_type:
                if req_type.has_subtype(type):
                    return True
        return False

    def get_root(self) -> MethodCall:
        if not self.parent:
            return self.stmt
        return self.parent.get_root()

    def is_fulfilled(self):
        return self.stmt.fulfilled() and self.parent == None

class JavaContext:
    def __init__(self, subtypes: Dict[Tuple[str, str], Set[str]], full_api_list: Set[JavaApi], special_class: Set[str]=set(), prob_gen_builtin=0.5, prob_gen=0.1) -> None:
        self.prob_gen_builtin = prob_gen_builtin # This is the probability of generating new variable when we already have this type of variable for builtin type
        self.prob_gen = prob_gen # This is the probability of generating new variable when we already have this type of variable for non-builtin type
        self.subtypes = subtypes

        constructors, methods = self.filter_by_constructor(full_api_list)
        self.constructor_dict = self.generate_constructor_dict(constructors)
        self.ret_dict = self.generate_return_dict(methods)

        self.builtin_dict = {
            "java.util.Map": [], 
            "java.util.List": [], 
            "java.lang.String": [],
            "java.lang.CharSequence": [], 
            "java.io.InputStream": [], 
            "java.awt.image.BufferedImage": ["java.io.IOException"],
            "java.io.Reader": []
        }
        self.special_class = special_class

        self.exist_stmts: Dict[JavaType, List[MethodCall]] = {}

        self.type_statements: Dict[JavaType, List[Tuple[MethodCall, List[MethodCall]]]] = {}

        self.candidates_dict: Dict[JavaType, List[MethodCall]] = {}
    
    def complete_statement(self, stmt: MethodCall) -> List[Statement]:
        if isinstance(stmt, ApiInvoke):
            if not stmt.is_static:
                fill_stmt, reuse = self.get_random_value(stmt.declaring_class)
                stmt.set_class_stmt(fill_stmt, reuse)
        for pos, arg_type in stmt.get_pos_args_types():
            fill_stmt, reuse = self.get_random_value(arg_type)
            stmt.set_pos_arg_stmt(pos, fill_stmt, reuse)
        
        result = self.__expand_stmt(stmt)
        self.__add_exist_stmts(result)
        return result

    def get_random_value(self, a_type: JavaType) -> Tuple[MethodCall, bool]:
        if x := self.__reuse_stmt(a_type):
            return x, True
        
        mc_list = self.__create_candidates(a_type)
        return self.__pick_from_candidates(mc_list), False

    def __pick_from_candidates(self, stmt_list: List[MethodCall]) -> MethodCall:
        node_pool: List[Node] = []
        next_node_pool: List[Node] = []
        for stmt in stmt_list:
            node_pool.append(Node(stmt, None, set()))
        
        candidates = []
        while True:
            node = node_pool.pop()

            while True:
                next_type, node = node.next_type()

                if not next_type:
                    break

                if x := self.__reuse_stmt(next_type):
                    node.set_next_stmt(x)
                else:
                    break

            if next_type:
                mc_list = self.__create_candidates(next_type)
                for mc in mc_list:
                    new_required_type = node.required_type.copy()
                    new_required_type.add(next_type)
                    new_node = Node(mc, node, new_required_type)
                    if not new_node.conflict(mc):
                        next_node_pool.append(new_node)
            else:
                candidates.append(node.get_root())
                for cand_node in node_pool:
                    t, n = cand_node.next_type()
                    if not t:
                        candidates.append(n.get_root())
                break

            if not node_pool:
                node_pool = next_node_pool
                next_node_pool = []

        if not candidates:
            raise Exception("Could not complete statement")

        return random.choice(candidates)

    def __reuse_stmt(self, a_type: JavaType) -> Optional[MethodCall]:
        live_stmts = self.__get_exist_stmts(a_type)
        if live_stmts:
            prob = random.random()
            builtin = self.is_builtin(a_type)
            if (builtin and prob > self.prob_gen_builtin) or ((not builtin) and prob > self.prob_gen):
                return random.choice(live_stmts)
        return None

    def __expand_stmt(self, stmt: MethodCall) -> List[MethodCall]:
        result = []
        for pos, arg_stmt in enumerate(stmt.arg_stmts):
            if not stmt.arg_reuse[pos]:
                result += self.__expand_stmt(arg_stmt)

        if isinstance(stmt, ApiInvoke) and not stmt.is_static:
            if not stmt.class_reuse:
                result += self.__expand_stmt(stmt.class_stmt)
        return result + [stmt]

    def __try_fulfill_statement(self, stmt: MethodCall, required_type: Set[JavaType], depth: int) -> Tuple[MethodCall, List[MethodCall]]:
        if depth > 5:
            return None, []
        
        # print(stmt)
        
        all_new_stmts = []

        for pos, arg_type in stmt.get_pos_args_types():
            arg_stmt, new_stmts, reuse = self.__get_random_var(arg_type, required_type, depth)
            if not arg_stmt:
                return None, []
            
            stmt.set_pos_arg_stmt(pos, arg_stmt)
            all_new_stmts += new_stmts

            if not reuse:
                all_new_stmts.append(arg_stmt)

            # if isinstance(stmt, ApiInvoke) and stmt.function_name == "createUser":
            #     print(new_stmts)

        if isinstance(stmt, ApiInvoke):
            if not stmt.is_static:
                class_stmt, new_stmts, reuse = self.__get_random_var(stmt.declaring_class, required_type, depth)
                if not class_stmt:
                    return None, []
                
                stmt.set_class_stmt(class_stmt)
                all_new_stmts += new_stmts

                # if stmt.function_name == "getUserManager":
                #     print(class_stmt)

                if not reuse:
                    all_new_stmts.append(class_stmt)

        return stmt, all_new_stmts
    
    def __get_random_var(self, type: JavaType, required_type: Set[JavaType], depth: int) -> Tuple[MethodCall, List[MethodCall], bool]:
        if type in required_type:
            return None, [], None

        live_stmts = self.exist_stmts[type]
        if live_stmts:
            prob = random.random()
            builtin = self.is_builtin(type)
            if (builtin and prob > self.prob_gen_builtin) or ((not builtin) and prob > self.prob_gen):
                return random.choice(live_stmts), [], True
        
        copy_stmt: bool = True
        # if not type in self.type_statements:
        if True:
            # if isinstance(type, ClassType) and type.className == "com.icegreen.greenmail.user.UserManager":
            #     print(1)
            candidate_methodcalls = self.__create_candidates(type)

            new_required_types = required_type.copy()
            new_required_types.add(type)
            fulfilled_candidates: List[Tuple[MethodCall, List[MethodCall]]] = [self.__try_fulfill_statement(candidate, new_required_types, depth + 1) for candidate in candidate_methodcalls]

            filtered_fulfilled_candidates: List[Tuple[MethodCall, List[MethodCall]]] = []
            for item in fulfilled_candidates:
                if item[0]:
                    filtered_fulfilled_candidates.append(item)

            if not filtered_fulfilled_candidates:
                return None, [], None

            min_new_var = len(filtered_fulfilled_candidates[0][1])
            for fc in filtered_fulfilled_candidates:
                if len(fc[1]) < min_new_var:
                    min_new_var = len(fc[1])
            
            min_cands: List[Tuple[MethodCall, List[MethodCall]]] = []
            for fc in filtered_fulfilled_candidates:
                if len(fc[1]) == min_new_var:
                    min_cands.append(fc)
            
            self.type_statements[type] = min_cands
            copy_stmt = False
        
        # min_cands = self.type_statements[type]
        # print(type)
        # print(min_cands)
        result = random.choice(min_cands)
        if copy_stmt:
            result = self.__copy_stmts(result)

        # print(type)
        # print(stmt)

        return result[0], result[1], False
        
    def filter_by_constructor(self, full_api_list: Set[JavaApi]) -> Tuple[List[JavaApi], List[JavaApi]]:
        constructors, methods = [], []
        for api in full_api_list:
            if api.is_constructor:
                if not api.is_abstract():
                    constructors.append(api)
            else:
                methods.append(api)
        return constructors, methods

    def generate_constructor_dict(self, constructors: List[JavaApi]) -> Dict[JavaType, List[JavaApi]]:
        constructor_dict: Dict[str, List[JavaApi]] = {}

        for constructor in constructors:
            if not constructor.is_public() or constructor.is_abstract():
                continue

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
            if not method.is_public():
                continue

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
            if type.is_primitive or type.className in self.builtin_dict:
                return True
        elif isinstance(type, ParameterizedType):
            className = type.rawType.className
            # special case for builtin type
            if className in self.builtin_dict:
                return True
        elif isinstance(type, ArrayType):
            if (type.rawType.is_primitive and not type.rawType.className in set(("double", "float", "char"))) or type.rawType.className in self.builtin_dict:
                return True
        return False
    
    def create_builtin(self, type: JavaType) -> MethodCall:
        if isinstance(type, ClassType):
            # String is a special class. We treat it as primitive
            if type.is_primitive:
                return ClassCreate(type, [], [])
            elif type.className in self.builtin_dict:
                return ClassCreate(type, [], [ClassType(item, {}, False) for item in self.builtin_dict[type.className]])
        elif isinstance(type, ParameterizedType):
            className = type.rawType.className
            # special case for builtin type
            if className in self.builtin_dict:
                return ClassCreate(type, [], [])
        elif isinstance(type, ArrayType):
            if type.rawType.is_primitive or type.rawType.className in self.builtin_dict:
                return ClassCreate(type, [], [])
        raise Exception("Not builtin type")

    def __create_candidates(self, type: JavaType) -> List[MethodCall]:
        candidates = []
        # if isinstance(type, ClassType) and type.className == "org.antlr.v4.runtime.CharStream":
        #     print(1)
        if type in self.candidates_dict:
            return [stmt.copy() for stmt in self.candidates_dict[type]]
        
        if type in self.ret_dict:
            candidates += [JavaFactory.api_to_apicall(api, self.subtypes) for api in self.ret_dict[type]]

        if isinstance(type, ArrayType):
            stmt = ArrayCreate(type)
            candidates.append(stmt)
        elif self.is_builtin(type):
            stmt = self.create_builtin(type)
            candidates.append(stmt)
        else:
            if type in self.constructor_dict:
                apis = self.constructor_dict[type]
                candidates += [JavaFactory.api_to_classcreate(api, self.subtypes) for api in apis]
        
        self.candidates_dict[type] = candidates
        
        return candidates

    def __copy_var_alive(self, var_alive: Dict[JavaType, List[MethodCall]]):
        copy_var_alive = {}
        for key in var_alive:
            copy_var_alive[key] = var_alive[key].copy()
        return copy_var_alive

    def __copy_stmts(self, cand: Tuple[MethodCall, List[MethodCall]]):
        stmt, new_stmts = cand
        return stmt.copy(), [s.copy() for s in new_stmts]

    def __add_exist_stmts(self, all_stmts: List[MethodCall]):
        for stmt in all_stmts:
            ret_type = stmt.ret_type
            if not ret_type in self.exist_stmts:
                self.exist_stmts[ret_type] = []
            self.exist_stmts[ret_type].append(stmt)

    def __get_exist_stmts(self, type: JavaType) -> List[MethodCall]:
        results = []
        for key_type in self.exist_stmts:
            if type.has_subtype(key_type):
                results += self.exist_stmts[key_type]
        return results
