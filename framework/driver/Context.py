from typing import List, Set, Dict, Tuple, Optional
import random

from . import Type, PointerType, Variable, BuffDecl, Statement, Value, NullConstant, Buffer

class Context:
    # trace the variable alives in this buffers within the context
    buffs_alive = Set[Buffer]
    # trace indexes to create new unique vars
    buffs_counter = Dict[Type, int]

    POINTER_STRATEGY_NULL = 0
    POINTER_STRATEGY_ARRAY = 1
    POINTER_STRATEGY_DEP = 2

    def __init__(self):
        self.buffs_alive = set()
        self.buffs_counter = {}
        self.stub_void = Type("void")
        self.poninter_strategies = [Context.POINTER_STRATEGY_NULL, 
                                    Context.POINTER_STRATEGY_ARRAY]
                                    # Context.POINTER_STRATEGY_DEP]

        # special case a buffer of void variables
        self.buffer_void = Buffer("buff_void", 1, self.stub_void)
        self.buffs_alive.add(self.buffer_void)

        # TODO: make this from config?
        self.MAX_ARRAY_SIZE = 1024
        # self.MAX_ARRAY_SIZE = 10

        # TODO: map buffer and input
        # self.buffer_map = {}

    def create_new_array(self, type):
        buff_counter = self.buffs_counter.get(type, 0)

        buff_name = f"{type.token}_{buff_counter}"

        new_buffer = Buffer(buff_name, self.MAX_ARRAY_SIZE, type)

        self.buffs_alive.add(new_buffer)
        self.buffs_counter[type] = buff_counter + 1

        return new_buffer

    def create_new_val(self, type: Type):

        # in case of void, I just return a void from a buffer void
        if type == self.stub_void:
            return self.buffer_void[0]

        buffer = self.create_new_array(type)

        # for the time being, I always return the first element
        return buffer[0]

    def get_allocated_size(self):
        return sum([ v.get_allocated_size() for v in self.vars_alive ])

    def has_vars_type(self, type: Type):
        for v in self.buffs_alive:
            if v.get_type() == type:
                return True

        return False

    def has_buffer_type(self, type: Type):
        for b in self.buffs_alive:
            if b.get_type() == type:
                return True

        return False

    def get_random_buffer(self, type: Type) -> Buffer:
        return random.choice([b for b in self.buffs_alive if b.get_type() == type])
    
    def get_random_var(self, type: Type) -> Variable:
        return self.get_random_buffer(type)[0]

    def randomly_gimme_a_var(self, type: Type, towhom) -> Value:

        v = None

        if isinstance(type, PointerType):
            tt = type.get_pointee_type()

            a_choice = random.choice(self.poninter_strategies)
            # just NULL
            if a_choice == Context.POINTER_STRATEGY_NULL:
                v = NullConstant(tt)
            # a vector
            elif a_choice == Context.POINTER_STRATEGY_ARRAY:
                if random.getrandbits(1) == 0 or not self.has_buffer_type(tt):
                    vp = self.create_new_array(tt)
                else:
                    vp = self.get_random_buffer(tt)

                v = vp.get_address()

        else:
            # if v not in context -> just create
            if not self.has_vars_type(type):
                # print(f"=> {t} not in context, new one")
                v = self.create_new_val(type)
            else:
                # I might get an existing one
                if random.getrandbits(1) == 1:
                    # print(f"=> wanna pick a random {t} from context")
                    v = self.get_random_var(type)
                # or create a new var
                else:
                    # print(f"=> decided to create a new {t}")
                    v = self.create_new_val(type)

        if v is None:
            raise Exception("v was not assigned!")

        return v
    
    def generate_def_buffer(self) -> List[Statement]:
        return [BuffDecl(x) for x in self.buffs_alive if x.get_token()!= self.stub_void]
        