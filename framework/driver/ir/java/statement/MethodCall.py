from abc import abstractmethod
from typing import List
from driver.ir import Statement
from driver.ir.java.type import JavaType, ClassType


class MethodCall(Statement):
    s_id: int = 0

    def __init__(self, declaring_class: JavaType, ret_type: JavaType, arg_types: List[JavaType], exceptions: List[ClassType]):
        self.declaring_class = declaring_class
        self.arg_types = arg_types
        self.exceptions = exceptions
        self.ret_type = ret_type

        self.class_stmt: 'MethodCall' = None
        self.arg_stmts: List['MethodCall'] = [None for _ in arg_types]

        self.class_reuse: bool = False
        self.arg_reuse: List[bool] = [False for _ in arg_types]

        self.id = MethodCall.s_id
        MethodCall.s_id += 1

        self.next_fulfill_pos = -1

    def set_next_stmt(self, stmt: 'MethodCall', reuse: bool=False):
        if self.next_fulfill_pos == -1:
            self.set_class_stmt(stmt, reuse)
        else:
            self.set_pos_arg_stmt(self.next_fulfill_pos, stmt, reuse)
        self.next_fulfill_pos += 1

    def get_next_type(self):
        if self.fulfilled():
            return None
        if self.next_fulfill_pos == -1:
            return self.declaring_class
        return self.arg_types[self.next_fulfill_pos]

    def get_pos_args_types(self):
        return enumerate(self.arg_types)
    
    def set_pos_arg_stmt(self, pos: int, stmt: 'MethodCall', reuse: bool=False):
        if pos < 0 or pos >= len(self.arg_stmts):
            raise Exception(f"{pos} out of range [0, {len(self.arg_stmts)})")

        # I must ensure the value is coherent with the argument type
        assert self.arg_types[pos].has_subtype(stmt.ret_type)

        self.arg_stmts[pos] = stmt
        self.arg_reuse[pos] = reuse

    def set_class_stmt(self, class_stmt: 'MethodCall', reuse: bool=False):

        assert self.declaring_class.has_subtype(class_stmt.ret_type)
        
        self.class_stmt = class_stmt
        self.class_reuse = reuse

    def fulfilled(self):
        return self.next_fulfill_pos >= len(self.arg_stmts)

    def __hash__(self):
        arg_lst = []
        arg_lst += [hash(a) for a in self.arg_types]
        arg_lst += [hash(self.declaring_class)]
        arg_lst += [hash(self.ret_type)]
        arg_lst += [hash(a) for a in self.exceptions]
        arg_lst += [hash(self.id)]
        return hash(tuple(arg_lst))
    
    @abstractmethod
    def get_all_type(self) -> List[JavaType]:
        pass

    @abstractmethod
    def copy(self) -> 'MethodCall':
        raise Exception("Not Override function")

    def deep_copy(self):
        stmt = self.copy()
        stmt.class_stmt = self.class_stmt
        for pos, arg_stmt in enumerate(self.arg_stmts):
            stmt.arg_stmts[pos] = arg_stmt
        stmt.next_fulfill_pos = self.next_fulfill_pos
        for pos, reuse in enumerate(self.arg_reuse):
            stmt.arg_reuse[pos] = reuse
        stmt.class_reuse = self.class_reuse
        return stmt
