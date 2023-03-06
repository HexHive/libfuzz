from typing import List, Set, Dict, Tuple, Optional

from driver.ir import Type, PointerType, Variable

from common import AccessTypeSet, AccessType, Access, ValueMetadata

class Conditions:
    # conditions that have WRITE or RET
    ats: AccessTypeSet
    is_array: bool
    is_malloc_size: bool
    is_file_path: bool
    len_depends_on: Variable
    
    def __init__(self, mdata: ValueMetadata):
        self.ats = AccessTypeSet()
        self.add_conditions(mdata.ats)
        self.is_array = mdata.is_array
        self.is_malloc_size = mdata.is_malloc_size
        self.is_file_path = mdata.is_file_path
        self.len_depends_on = None 

    def get_sub_fields(self, f_prev):
        f_prev_len = len(f_prev)
        f_prev_sub = []
        for x in self.ats:
            if f_prev == x.fields[:f_prev_len]:
                f_prev_sub += [x.fields]
        return f_prev_sub

    def is_compatible_with(self, r_cond: ValueMetadata) -> bool:

        if self.is_array != r_cond.is_array:
            return False

        # r_requirements = set([at for at in r_cond if at.access == Access.READ])
        r_requirements = set([at for at in r_cond.ats if at.access == Access.WRITE])
        # holding_condition = set([at for at in self.ats if at.access in [Access.WRITE, Access.RETURN]])

        matching_requirements = 0
        unmatching_requirements = set()

        for r in r_requirements:
            req_found = False
            for h in self.ats:
                if r.fields == h.fields:
                    matching_requirements += 1
                    req_found = True
            
            if not req_found:
                unmatching_requirements.add(r)


        real_unmatched = set()

        for u in unmatching_requirements:
            f_prev = u.fields[:-1]

            if len(u.fields) > 0 and u.fields[-1] == -1:
                f_prev_len = len(f_prev)
                f_prev_sub = self.get_sub_fields(f_prev)
                if len(f_prev_sub) > 0:
                    matching_requirements += 1
            else:
                while True:
                    f_prev_len = len(f_prev)
                    f_prev_sub = self.get_sub_fields(f_prev)
                    if len(f_prev_sub) != 0:
                        if len(f_prev_sub) == 1 and f_prev_sub[0] == f_prev:
                            matching_requirements += 1
                            # print(f"ok {f_prev} for {u}")
                            break
                        else:
                            # print(f"break1 {u}")
                            real_unmatched.add(u)
                            break
                    elif f_prev_len == 0:
                        # print(f"break2 {u}")
                        real_unmatched.add(u)
                        break
                    else:
                        # print(f_prev)
                        f_prev = f_prev[:-1]
                        f_prev_len = len(f_prev)

        # if matching_requirements != len(r_requirements):
        #     print("OK FINE")
        #     from IPython import embed; embed(); exit(1)

        return matching_requirements == len(r_requirements)

    def add_conditions(self, r_ats: AccessTypeSet):
        # I accumulate only WRITE and RET conditions
        holding_condition = set([at for at in r_ats if at.access == Access.WRITE])
        new_ats = AccessTypeSet(holding_condition)

        self.ats = self.ats.union(new_ats)

    @staticmethod
    def is_unconstraint(cond: ValueMetadata) -> bool:

        if len(cond.ats) == 0:
            return True 
            
        if len(cond.ats) == 1:
            at = list(cond.ats)[0]
            if at.access == Access.READ and at.fields == []:
                return True

        return False