from typing import List, Set, Dict, Tuple, Optional

import random, copy, string

from driver import Context
from driver.ir import Variable, Type, Value, PointerType, AllocType
from driver.ir import Address, NullConstant, Buffer, ConstStringDecl
from driver.ir import BuffDecl, BuffInit, FileInit, Statement, DynArrayInit
from . import Conditions
from common.conditions import *

class RunningContext(Context):
    variables_alive:    List[Variable]
    var_to_cond:        Dict[Variable, Conditions]
    file_path_buffers:  Set[Buffer]
    new_vars:           Set[Tuple[Variable, Conditions]]
    const_strings:      Dict[Variable, str]
    # len_dependency:     Dict[Variable, Variable]

    # static dictionary
    type_to_hash:        Dict[str, str]

    def __init__(self):
        super().__init__()
        self.variables_alive = []
        self.var_to_cond = {}

        self.file_path_buffers = set()
        self.new_vars = set()
        self.const_strings = {}

#        self.len_dependency = {}

    # override of Context method
    def has_vars_type(self, type: Type, cond: ValueMetadata) -> bool:

        # FLAVIO: I think this should be like that!
        # TODO: Extract "base" type with a dedicated method?
        tt = None
        if isinstance(type, PointerType):
            if type.get_pointee_type().is_incomplete:
                tt = type
            else:
                tt = type.get_pointee_type()
        else:
            tt = type
            
        if tt is None:
            raise Exception("can't find a type for 'tt'")
        # tt = type

        for v in self.variables_alive:
            if ((v.get_type() == tt or v.get_type() == type) and 
                self.var_to_cond[v].is_compatible_with(cond)):
                return True

        # if cond.is_array:
        #     from IPython import embed; embed(); exit(1)

        return False

    def get_value_that_satisfy(self, type: Type,
            cond: AccessTypeSet) -> Optional[Value]:

        # print("Debug get_value_that_satisfy")
        # from IPython import embed; embed(); exit()

        tt = None
        if isinstance(type, PointerType):
            if type.get_pointee_type().is_incomplete:
                tt = type
            else:
                tt = type.get_pointee_type()
        else:
            tt = type
            
        if tt is None:
            raise Exception("can't find a type for 'tt'")

        vars = set()

        for v in self.variables_alive:
            if ((v.get_type() == tt or v.get_type() == type) and
                self.var_to_cond[v].is_compatible_with(cond)):
                vars.add(v)

        if len(vars) == 0:
            return None
        else:
            var = random.choice(list(vars))
            if isinstance(type, PointerType):
                return var.get_address()
            return var

    def get_value_that_strictly_satisfy(self, type: Type,
            cond: AccessTypeSet) -> Optional[Value]:

        # print("Debug get_value_that_strictly_satisfy")
        # from IPython import embed; embed(); exit()

        vars = set()

        for v in self.variables_alive:
            if (v.get_type() == type and 
                self.var_to_cond[v].is_compatible_with(cond)):
                vars.add(v)

        if len(vars) == 0:
            return None
        else:
            var = random.choice(list(vars))
            if isinstance(type, PointerType):
                return var.get_address()
            return var


    def add_variable(self, val: Value, cond: ValueMetadata):

        if not isinstance(val, Variable):
            raise Exception(f"{val} is not a Variable! :(")

        seek_val = None
        for v in self.variables_alive:
            if v == val:
                seek_val = v
                break

        if seek_val is None:
            self.variables_alive += [val]
            if cond != None:
                self.var_to_cond[val] = Conditions(cond)
        else:
            if cond != None:
                self.var_to_cond[val].add_conditions(cond.ats)
                self.var_to_cond[val].is_array = cond.is_array
                self.var_to_cond[val].is_malloc_size = cond.is_malloc_size
                self.var_to_cond[val].is_file_path = cond.is_file_path
                # self.var_to_cond[val].len_depends_on = cond.len_depends_on

        # TODO: handle dependency fields here?

    def try_to_get_var(self, type: Type, cond: ValueMetadata,
                        is_ret: bool = False) -> Value:

        # from IPython import embed; embed(); exit(1)

        # TODO: this has to include logic to handl arrays, malloc, file
        # diependencies, etc

        is_sink = self.is_sink(cond)

        val = None

        # for variables used in ret -> I take any compatible type and overwrite
        # their conditions
        if is_ret:

            # if I need a void for return, don't bother too much
            if type == self.stub_void:
                val = NullConstant(self.stub_void)
            else:
                val = self.randomly_gimme_a_var(type, cond, is_ret)

        elif is_sink:
            val = self.get_value_that_strictly_satisfy(type, cond)
            if val is None:
                if (Conditions.is_unconstraint(cond) and 
                    not type.is_incomplete):
                    val = self.randomly_gimme_a_var(type, cond, is_ret)
                else:
                    raise ConditionUnsat()
        elif self.has_vars_type(type, cond):
            # print("elif self.has_vars_type(type, cond):")
            # val = self.get_value_that_satisfy(type, cond)
            # if val is None:
            #     if (Conditions.is_unconstraint(cond) and 
            #         not type.is_incomplete):
            try:
                val = self.randomly_gimme_a_var(type, cond, is_ret)
            except Exception as e:
                print("randomly_gimme_a_var empty?!")
                from IPython import embed; embed(); exit(1)
                # else:
                #     raise ConditionUnsat()
        else:
            # print("else:")
            if isinstance(type, PointerType):
                tt = type.get_pointee_type()  
            else:
                tt = type
            # TODO: check if the ats allow to generate an object
            if tt.is_incomplete and not is_ret:
                raise ConditionUnsat()
            else:
                val = self.create_new_var(type, cond)
                if (isinstance(val, Variable) and 
                    isinstance(val.get_type(), PointerType)):
                    val = val.get_address()

        if val == None:
            raise Exception("Val unset")

        if cond.is_file_path and not isinstance(val, NullConstant):
            # print("cond.is_file_path")
            # from IPython import embed; embed(); exit(1)

            var = None
            if isinstance(val, Address):
                var = val.get_variable()
            elif isinstance(val, Variable):
                var = val
            else:
                raise Exception("Excepted Address or Variable")

            # buff = var.get_buffer()
            # buff.alloctype = AllocType.GLOBAL
            
            buff = var.get_buffer()
            (len_dep, len_cond) = self.create_dependency_length_variable()

            if buff.get_type().token != "char*":
                print("checking type")
                from IPython import embed; embed(); exit(1)

            self.file_path_buffers.add(buff)
            self.new_vars.add((var, len_dep, len_cond))

            length = 20
            letters = string.ascii_lowercase
            file_name = ''.join(random.choice(letters) for i in range(length)) + ".bin"

            # TODO: add folder to the file lenght
            self.const_strings[var] = file_name

        return val

    def create_dependency_length_variable(self):
        len_type = Type("size_t", 8)
        ats = AccessTypeSet()
        mdata = ValueMetadata(ats, False, False, False, "")
        return (self.create_new_var(len_type, mdata), mdata)

    def create_new_buffer(self, type: Type, cond: ValueMetadata):
        # if isinstance(type, PointerType):
        #     raise Exception(f"This function creates buffers only for base types (no pointers!) {type}")

        alloctype = AllocType.STACK
        if (isinstance(type, PointerType) and 
            (type.get_base_type().is_incomplete or cond.len_depends_on != "")):
            alloctype = AllocType.HEAP

        buff_counter = self.buffs_counter.get(type, 0)
        
        pnt = ""
        tt = type
        ps = ""
        while isinstance(tt, PointerType):
            ps += "p"
            tt = tt.get_pointee_type()
        if ps != "":
            pnt = f"_{ps}"
        cst = "c" if type.is_const else ""
        # so far, only HEAP and STACK
        heap = "h" if alloctype == AllocType.HEAP else "s"

        buff_name = f"{type.token}{pnt}_{cst}{heap}{buff_counter}"
        buff_name = buff_name.replace(" ", "")
        if cond.is_array:
            new_buffer = Buffer(buff_name, self.MAX_ARRAY_SIZE, type, alloctype)
        else:
            new_buffer = Buffer(buff_name, 1, type, alloctype)

        self.buffs_alive.add(new_buffer)
        self.buffs_counter[type] = buff_counter + 1

        return new_buffer

    def create_new_var(self, type: Type, cond: ValueMetadata):

        # in case of void, I just return a void from a buffer void
        if type == self.stub_void:
            return self.buffer_void[0]

        buffer = self.create_new_buffer(type, cond)

        # for the time being, I always return the first element
        return buffer[0]

    def has_dereference(self, cond: ValueMetadata):

        has_deref = False
        for at in cond.ats:
            if at.fields == [-1]:
                has_deref = True
                break

        return has_deref

    def randomly_gimme_a_var(self, type: Type, cond: ValueMetadata,
        is_ret: bool = False) -> Value:

        v = None

        if isinstance(type, PointerType):
            is_incomplete = False
            if type.get_pointee_type().is_incomplete or is_ret:
                tt = type
                if not is_ret:
                    is_incomplete = type.get_pointee_type().is_incomplete
            else:
                tt = type.get_pointee_type()
                is_incomplete = tt.is_incomplete

            # If asking for ret value, I always need a pointer
            if (is_ret or cond.is_file_path or 
                self.has_dereference(cond) or
                cond.len_depends_on != ""):
                a_choice = Context.POINTER_STRATEGY_ARRAY
            else:
                a_choice = random.choice(self.poninter_strategies)

            # just NULL
            if a_choice == Context.POINTER_STRATEGY_NULL:
                v = NullConstant(tt)
            # a vector
            elif a_choice == Context.POINTER_STRATEGY_ARRAY:
                # if random.getrandbits(1) == 0 or not self.has_buffer_type(tt):
                if ((random.getrandbits(1) == 0 or
                    not self.has_vars_type(type, cond)) and 
                    not is_incomplete):
                    try:
                        # print("self.create_new_buffer(tt, cond)")
                        vp = self.create_new_buffer(type, cond)
                    except Exception as e:
                        print("within 'a_choice == Context.POINTER_STRATEGY_ARRAY'")
                        from IPython import embed; embed(); exit()
                else:
                    # print("get_random_buffer")
                    vp = self.get_random_buffer(type, cond)

                v = vp.get_address()

        else:
            # if "type" is incomplete, I can't get its value at all.
            # besides void!
            if type.is_incomplete and type != self.stub_void:
                raise Exception(f"Cannot get a value from {type}!")
 
            # if v not in context -> just create
            if not self.has_vars_type(type, cond):
                # print(f"=> {t} not in context, new one")
                try:
                    v = self.create_new_var(type, cond)
                except:
                    print("within 'not self.has_vars_type(type):'")
                    from IPython import embed; embed(); exit()
            else:
                # I might get an existing one
                if random.getrandbits(1) == 1:
                    # print(f"=> wanna pick a random {t} from context")
                    v = self.get_random_var(type, cond)
                # or create a new var
                else:
                    # print(f"=> decided to create a new {t}")
                    v = self.create_new_var(type, cond)

        if v is None:
            raise Exception("v was not assigned!")

        return v

    def get_random_buffer(self, type: Type, cond: ValueMetadata) -> Buffer:
        return self.get_random_var(type, cond).buffer
        # tt = None
        # if isinstance(type, PointerType):
        #     if type.get_pointee_type().is_incomplete:
        #         tt = type
        #     else:
        #         tt = type.get_pointee_type()
        # else:
        #     tt = type

        # suitable_buff = []

        # for b in self.buffs_alive:
        #     var_b = b[0]
        #     if var_b not in self.var_to_cond:
        #         continue
        #     if (b.get_type() == tt and
        #         self.var_to_cond[var_b].is_compatible_with(cond)):
        #         suitable_buff += [b]

        # return random.choice(suitable_buff)
    
    def get_random_var(self, type: Type, cond: ValueMetadata) -> Variable:

        suitable_vars = []

        tt = None
        if isinstance(type, PointerType):
            if type.get_pointee_type().is_incomplete:
                tt = type
            else:
                tt = type.get_pointee_type()
        else:
            tt = type

        for v in self.variables_alive:
            if ((v.get_type() == tt or v.get_type() == type)
                and self.var_to_cond[v].is_compatible_with(cond)):
                suitable_vars += [v]

        return random.choice(suitable_vars)

        # return self.get_random_buffer(type, cond)[0]

    def infer_type(self, type, cond, fields):
        type_str = ""
        type_hash = ""

        if fields == []:
            type_strings = set()
            for x in cond.ats.access_type_set:
                if x.fields == []:
                    type_strings.add(x.type_string)

            if len(type_strings) == 0:
                type_str = type.token
                length = 20
                letters = string.ascii_lowercase
                type_hash = ''.join(random.choice(letters) for i in range(length))
            else:
                type_hash = None
                for t in type_strings:
                    if t in RunningContext.type_to_hash:
                        type_str = t
                        type_hash = RunningContext.type_to_hash[t]
                        break

            if not type_hash:
                raise Exception(f"Cannot find type hash for {type_strings}")
            
        elif fields == [-1]:
            
            type_strings = set()
            for x in cond.ats.access_type_set:
                if x.fields == []:
                    type_strings.add(x.type_string)

            if len(type_strings) == 0:
                raise Exception("Not found type at [-1]")

            type_strs = []
            type_hash = None
            for t in type_strings:
                # I care only of 1-d pointers 
                if "*" not in t:
                    continue
                if t in RunningContext.type_to_hash:
                    type_strs += [t[:-1]]
            
            if len(type_str):
                raise Exception(f"Cannot find type hash for {type_strings}")

            type_hash = None
            type_str = None
            for s in type_strs:
                if s in RunningContext.type_to_hash:
                    type_hash = RunningContext.type_to_hash[s]
                    type_str = s
                    break

            # if I can't find anchestor, just produce a random hash
            if type_hash is None:
                length = 20
                letters = string.ascii_lowercase
                type_hash = ''.join(random.choice(letters) for i in range(length))
            
            if type_str is None:
                if len(type_strs) == 1:
                    type_str = type_strs[0]
                else:
                    from IPython import embed; embed(); exit(1)
                    raise Exception(f"Really don't know what to do with {type_strings}")
                

        else:
            raise Exception(f"Cannot handle {fields} field type inferring")

        RunningContext.type_to_hash[type_str] = type_hash

        return (type_str, type_hash)

    def update(self, val: Optional[Value], cond: ValueMetadata,
        is_ret: bool = False):

        # NullConstant does not have conditions
        if isinstance(val, NullConstant):
            return

        synthetic_cond = None

        var = None
        if isinstance(val, Variable):
            type = val.get_type()
            (type_str, type_hash) = self.infer_type(type, cond, [])
            x = AccessType(Access.WRITE, [], type_hash, type_str)
            synthetic_cond = AccessTypeSet(set([x]))
            var = val
        elif isinstance(val, Address):
            type = val.get_variable().get_type()
            (type_str, type_hash) = self.infer_type(type, cond, [])
            x0 = AccessType(Access.WRITE, [], type_hash, type_str)
            (type_str, type_hash) = self.infer_type(type, cond, [-1])
            x1 = AccessType(Access.WRITE, [-1], type_hash, type_str)
            x1.parent = x0
            synthetic_cond = AccessTypeSet(set([x0, x1]))
            var = val.get_variable()
        else:
            raise Exception(f"I don't know this val: {val}")
            
        is_sink = self.is_sink(cond)

        if is_ret and var in self.variables_alive:
            del self.var_to_cond[var]
            self.variables_alive.remove(var)

        already_present = var in self.var_to_cond
        self.add_variable(var, cond)

        if already_present and is_sink:
            del self.var_to_cond[var]
            self.variables_alive.remove(var)

        if var in self.var_to_cond and synthetic_cond is not None:
            self.var_to_cond[var].add_conditions(synthetic_cond)

            # from IPython import embed; embed(); exit(1);
            # import pdb; pdb.set_trace(); exit(1);

    def generate_buffer_init(self) -> List[Statement]:
        buff_init = []

        # I have to handle dynamic arrays separately
        dynamic_buff = set()
        for var, cond in self.var_to_cond.items():
            if cond.len_depends_on is not None:
                var_len = cond.len_depends_on
                for x in [var, var_len]:
                    buff = None
                    if isinstance(x, Address):
                        buff = x.get_variable().get_buffer()
                    elif isinstance(x, Variable):
                        buff = x.get_buffer()
                    else:
                        raise Exception(f"{x} did not expected here!")

                    dynamic_buff.add(buff)
        
        # # buffers for file paths
        # for b in self.file_path_buffers:
        #     dynamic_buff.add(b)
        #     len_var = self.var_to_cond[b[0]].len_depends_on
        #     dynamic_buff.add(len_var.get_buffer())

        # # buffers for malloc-like objects
        # for b, b_len in self.len_dependency.items():
        #     for x in [b, b_len]:
        #         buff = None
        #         if isinstance(x, Address):
        #             buff = x.get_variable().get_buffer()
        #         elif isinstance(x, Variable):
        #             buff = x.get_buffer()
        #         else:
        #             raise Exception(f"{x} did not expected here!")

        #         dynamic_buff.add(buff)

        # first init static buffers
        for x in self.buffs_alive:
            t = x.get_type()

            if isinstance(t, PointerType) and t.get_base_type().is_incomplete:
                continue

            if t.is_incomplete:
                continue
            
            if t == self.stub_void:
                continue

            if x in dynamic_buff:
                continue

            buff_init += [BuffInit(x)]

        for var, cond in self.var_to_cond.items():
            len_var = cond.len_depends_on
            if len_var is None:
                continue
            
            buff = None
            if isinstance(var, Address):
                buff = var.get_variable().get_buffer()
            elif isinstance(var, Variable):
                buff = var.get_buffer()
            else:
                raise Exception(f"{var} did not expected here (final)!")

            if buff in self.file_path_buffers:
                buff_init += [FileInit(buff, len_var)]
            else:
                buff_init += [DynArrayInit(buff, len_var)]

        # # then init file pointers
        # for b in self.file_path_buffers: 
        #     len_var = self.var_to_cond[b[0]].len_depends_on
        #     buff_init += [FileInit(b, len_var)]

        # # finally init dynamic buffers
        # for b, b_len in self.len_dependency.items():
        #     buff = None
        #     if isinstance(b, Address):
        #         buff = b.get_variable().get_buffer()
        #     elif isinstance(b, Variable):
        #         buff = b.get_buffer()
        #     else:
        #         raise Exception(f"{b} did not expected here (final)!")
        #     buff_init += [DynArrayInit(buff, b_len)]

        return buff_init

    def generate_buffer_decl(self) -> List[Statement]:
        buff_decl = []

        for x in self.buffs_alive:
            if x.get_type() == self.stub_void:
                continue

            if x[0] in self.const_strings:
                x_val = self.const_strings[x[0]]
                buff_decl += [ConstStringDecl(x, x_val)]
            else:
                buff_decl += [BuffDecl(x)]
            
        return buff_decl


    # NOTE: this oracle infers if the variable with the access types (cond) can
    # be considered a sink
    def is_sink(self, cond: ValueMetadata):
        deletes_root = any([c.access == Access.DELETE and c.fields == [] 
                            for c in cond.ats])
        creates_root = any([c.access == Access.CREATE and c.fields == [] 
                            for c in cond.ats])
        return deletes_root and not creates_root

    def __copy__(self):
        raise Exception("__copy__ not implemented")
        
class ConditionUnsat(Exception):
    """ConditionUnsat, can't find a suitable variable in the RunningContext"""
    pass