
#ifndef INCLUDE_DOM_DOMINATORS_H_
#define INCLUDE_DOM_DOMINATORS_H_

#include "GenericDominatorTy.h"

class Dominator : public GenericDominatorTy {
    private:
        ICFGNodeSet ahead(ICFGEdge*);
        void buildDom();
        inline string getDomName() {return "Dominator";}

    public:
        Dominator(BVDataPTAImpl* pt, FunEntryICFGNode *fun_entry)
         : GenericDominatorTy(pt) {
            setEntryNode(fun_entry);
        }

};

#endif /* INCLUDE_DOM_DOMINATORS_H_ */