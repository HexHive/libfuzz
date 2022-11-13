from typing import List, Set, Dict, Tuple, Optional

from driver.ir import Type, PointerType

from common import AccessTypeSet, AccessType, Access

class Conditions:
    # conditions that have WRITE or RET
    ats: AccessTypeSet
    
    def __init__(self, r_ats: AccessTypeSet):
        self.ats = AccessTypeSet()
        self.add_conditions(r_ats)

    def are_compatible_with(self, r_ats: AccessTypeSet) -> bool:

        r_requirements = set([at for at in r_ats if at.access == Access.READ])
        # holding_condition = set([at for at in self.ats if at.access in [Access.WRITE, Access.RETURN]])

        matching_requirments = 0

        for r in r_requirements:
            for h in self.ats:
                if r.fields == h.fields:
                    matching_requirments += 1

        return matching_requirments == len(r_requirements)

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