from typing import List, Set, Dict, Tuple, Optional

from driver.ir import Type, PointerType

from common import AccessTypeSet, AccessType, Access

class Conditions:
    # conditions that have WRITE or RET
    ats: AccessTypeSet
    
    def __init__(self, r_ats: AccessTypeSet):
        self.ats = AccessTypeSet()
        self.add_conditions(r_ats)

    def get_sub_fields(self, f_prev):
        f_prev_len = len(f_prev)
        f_prev_sub = []
        for x in self.ats.access_type_set:
            if f_prev == x.fields[:f_prev_len]:
                f_prev_sub += [x.fields]
        return f_prev_sub

    def are_compatible_with(self, r_ats: AccessTypeSet) -> bool:

        r_requirements = set([at for at in r_ats if at.access == Access.READ])
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


        matching_requirements2 = set()

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
                            matching_requirements2.add(u)
                            break
                    elif f_prev_len == 0:
                        # print(f"break2 {u}")
                        matching_requirements2.add(u)
                        break
                    else:
                        # print(f_prev)
                        f_prev = f_prev[:-1]
                        f_prev_len = len(f_prev)

        # if len(r_requirements) == 41:
        #     print("OK FINE")
        #     from IPython import embed; embed(); exit(1)

        return matching_requirements == len(r_requirements)

    def add_conditions(self, r_ats: AccessTypeSet):
        # I accumulate only WRITE and RET conditions
        holding_condition = set([at for at in r_ats if at.access == Access.WRITE])
        new_ats = AccessTypeSet(holding_condition)

        self.ats = self.ats.union(new_ats)

    @staticmethod
    def is_unconstraint(cond: AccessTypeSet) -> bool:

        if len(cond) == 0:
            return True 
            
        if len(cond) == 1:
            at = list(cond)[0]
            if at.access == Access.READ and at.fields == []:
                return True

        return False