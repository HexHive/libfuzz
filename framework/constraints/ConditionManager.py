from typing import Set, Dict

from driver.ir import Type, ApiCall, Buffer, PointerType
from driver.factory import Factory

from common import Api, FunctionConditionsSet, ValueMetadata, Access
from common import FunctionConditionsSet, DataLayout

class ConditionManager:
    sink_map            : Dict[Type, Api]
    sinks               : Set[Api]
    api_list            : Set[Api]
    conditions          : FunctionConditionsSet

    _instance           : "ConditionManager" = None

    def __init__(self):
        raise Exception("ConditionManager can be obtained through instance() class method")

    @classmethod
    def instance(cls):
        if cls._instance is None:
            cls._instance = cls.__new__(cls)
        return cls._instance
    
    def setup(self, api_list: Set[Api], api_list_all: Set[Api],
              conditions: FunctionConditionsSet):
        
        self.api_list = api_list
        self.api_list_all = api_list_all
        self.conditions = conditions

        self.init_sinks()
        self.init_source()

    def init_sinks(self):
        # sink map that links Type <=> (Sink)Api
        self.sink_map = {}
        self.sinks = set()

        get_cond = lambda x: self.conditions.get_function_conditions(
            x.function_name)

        for api in self.api_list_all:
            fun_cond = get_cond(api)
            if (len(api.arguments_info) == 1 and 
                self.is_return_sink(api.return_info.type) and
                self.is_a_sink_condition(fun_cond.argument_at[0])):
                arg = api.arguments_info[0]
                the_type = Factory.normalize_type(arg.type, arg.size, 
                                                  arg.flag, arg.is_const)
                self.sink_map[the_type] = api
                self.sinks.add(api)

        # print("init_sinks")
        # from IPython import embed; embed(); exit()

    def is_return_sink(self, token_type: str):
        if token_type == "void":
            return True
        
        if DataLayout.instance().is_enum_type(token_type):
            return True

        return False

    def is_sink(self, api_call: ApiCall) -> bool:
        return api_call.original_api in self.sinks

    def is_a_sink_condition(self, cond: ValueMetadata) -> bool:
        deletes_root = any([c.access == Access.DELETE and c.fields == [] 
                            for c in cond.ats])
        creates_root = any([c.access == Access.CREATE and c.fields == [] 
                            for c in cond.ats])
        return deletes_root and not creates_root    
    
    def find_cleanup_method(self, buff: Buffer, default: str = "free"):

        buff_type = buff.get_type()

        if buff_type not in self.sink_map:
            return default
        
        api_sink = self.sink_map[buff_type]
        return api_sink.function_name

    def is_source(self, cond: ValueMetadata):
        return (len([at for at in cond.ats
                if at.access == Access.CREATE and at.fields == []]) != 0)
    
    def get_source_api(self) -> Set[Api]:
        return self.source_api

    def init_source(self) -> Set[Api]:

        source_api = set()

        get_cond = lambda x: self.conditions.get_function_conditions(
            x.function_name)

        for api in self.api_list:
            # if DataLayout.instance().has_incomplete_type():
            #     if (not any(arg.is_type_incomplete for arg in api.arguments_info) 
            #         and api.return_info.is_type_incomplete):
            #         source_api.add(api)
            #     if (not any(arg.is_type_incomplete for arg in api.arguments_info) 
            #         and api.return_info.type == "void*"):
            #         source_api.add(api)
            # else:
            #     source_api.add(api)

            # if api.function_name == "bstr_builder_create":
            #     print("get_source_api")
            #     from IPython import embed; embed(); exit(1)

            # NOTE: some sinks could be misclassifed as source apis
            if api in self.sinks:
                continue

            fun_cond = get_cond(api)

            # if api.function_name == "htp_tx_req_get_param":
            #     print(f"get_source_api {api.function_name}")
            #     from IPython import embed; embed(); exit(1)

            num_arg_ok = 0
            for arg_p, arg in enumerate(api.arguments_info):
                the_type = Factory.normalize_type(arg.type, arg.size, arg.flag, arg.is_const)
                arg_cond = fun_cond.argument_at[arg_p]
                if isinstance(the_type, PointerType):
                    the_type = the_type.get_base_type()
                tkn = the_type.token
                if DataLayout.instance().is_primitive_type(tkn):
                    num_arg_ok += 1 
                elif DataLayout.instance().has_user_define_init(tkn):
                    num_arg_ok += 1 
                elif DataLayout.instance().is_enum_type(tkn):
                    num_arg_ok += 1 
                # elif (the_type.tag == TypeTag.STRUCT and
                #       DataLayout.instance().is_fuzz_friendly(tkn) and
                #       Conditions.is_unconstraint(arg_cond)):
                #     num_arg_ok += 1


            # I can initialize all the arguments
            if len(api.arguments_info) == num_arg_ok:
                source_api.add(api)

        # print("get_source_api")
        # from IPython import embed; embed(); exit(1)

        self.source_api = source_api
