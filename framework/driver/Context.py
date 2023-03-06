from typing import List, Set, Dict #, Tuple, Optional
import random, copy

from .ir import Type, PointerType, Variable, BuffDecl, BuffInit, Statement, Value, NullConstant, Buffer

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
        self.stub_char_array = PointerType("char*", Type("char", 8))
        self.poninter_strategies = [Context.POINTER_STRATEGY_NULL, 
                                    Context.POINTER_STRATEGY_ARRAY]
                                    # Context.POINTER_STRATEGY_DEP]

        # special case a buffer of void variables
        self.buffer_void = Buffer("buff_void", 1, self.stub_void)
        self.buffs_alive.add(self.buffer_void)

        # TODO: make this from config?
        # self.MAX_ARRAY_SIZE = 1024
        self.MAX_ARRAY_SIZE = 128

        # TODO: map buffer and input
        # self.buffer_map = {}

    def is_void_pointer(self, arg):
        return isinstance(arg, PointerType) and arg.get_pointee_type() == self.stub_void

    def get_null_constant(self):
        return NullConstant(self.stub_void)

    def create_new_buffer(self, type):
        # if isinstance(type, PointerType):
        #     raise Exception(f"This function creates buffers only for base types (no pointers!) {type}")

        buff_counter = self.buffs_counter.get(type, 0)
        
        pnt = "_p" if isinstance(type, PointerType) else ""
        cst = "c" if type.is_const else ""

        buff_name = f"{type.token}{pnt}_{cst}{buff_counter}"
        buff_name = buff_name.replace(" ", "")
        new_buffer = Buffer(buff_name, self.MAX_ARRAY_SIZE, type)

        self.buffs_alive.add(new_buffer)
        self.buffs_counter[type] = buff_counter + 1

        return new_buffer

    def create_new_var(self, type: Type):

        # in case of void, I just return a void from a buffer void
        if type == self.stub_void:
            return self.buffer_void[0]

        buffer = self.create_new_buffer(type)

        # for the time being, I always return the first element
        return buffer[0]

    def get_allocated_size(self):
        return sum([ b.get_allocated_size() for b in self.buffs_alive ])

    def has_vars_type(self, type: Type) -> bool:
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

    def randomly_gimme_a_var(self, type: Type, towhom, is_ret: bool = False) -> Value:

        v = None

        if isinstance(type, PointerType):
            if type.get_pointee_type().is_incomplete or is_ret:
                tt = type
            else:
                tt = type.get_pointee_type()

            if is_ret:
                a_choice = Context.POINTER_STRATEGY_ARRAY
            else:
                a_choice = random.choice(self.poninter_strategies)


            # just NULL
            if a_choice == Context.POINTER_STRATEGY_NULL:
                v = NullConstant(tt)
            # a vector
            elif a_choice == Context.POINTER_STRATEGY_ARRAY:
                if random.getrandbits(1) == 0 or not self.has_buffer_type(tt):
                    try:
                        vp = self.create_new_buffer(tt)
                    except Exception as e:
                        print("within 'a_choice == Context.POINTER_STRATEGY_ARRAY'")
                        from IPython import embed; embed(); exit()
                else:
                    vp = self.get_random_buffer(tt)

                v = vp.get_address()

        else:
            # if "type" is incomplete, I can't get its value at all.
            # besides void!
            if type.is_incomplete and type != self.stub_void:
                raise Exception(f"Cannot get a value from {type}!")
 
            # if v not in context -> just create
            if not self.has_vars_type(type):
                # print(f"=> {t} not in context, new one")
                try:
                    v = self.create_new_var(type)
                except:
                    print("within 'not self.has_vars_type(type):'")
                    from IPython import embed; embed(); exit()
            else:
                # I might get an existing one
                if random.getrandbits(1) == 1:
                    # print(f"=> wanna pick a random {t} from context")
                    v = self.get_random_var(type)
                # or create a new var
                else:
                    # print(f"=> decided to create a new {t}")
                    v = self.create_new_var(type)

        if v is None:
            raise Exception("v was not assigned!")

        return v
    
    def generate_buffer_decl(self) -> List[Statement]:
        return [BuffDecl(x) for x in self.buffs_alive if x.get_type() != self.stub_void]

    def generate_buffer_init(self) -> List[Statement]:
        # return [BuffInit(x) for x in self.buffs_alive if not x.get_type().is_incomplete and not isinstance(x.get_type(), PointerType) and x.get_type() != self.stub_void]

        buff_init = []

        for x in self.buffs_alive:
            t = x.get_type()

            if isinstance(t, PointerType) and t.get_base_type().is_incomplete:
                continue

            if t.is_incomplete:
                continue
            
            if t == self.stub_void:
                continue
            
            buff_init += [BuffInit(x)]

        return buff_init