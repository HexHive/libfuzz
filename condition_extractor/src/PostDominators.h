
#ifndef INCLUDE_PDOM_DOMINATORS_H_
#define INCLUDE_PDOM_DOMINATORS_H_

#include "GenericDominatorTy.h"


class PostDominator : public GenericDominatorTy {
    protected:
        FunExitICFGNode* exit_node;
        ICFGNodeSet behind(ICFGEdge*);
        void buildDom();
        inline string getDomName() {return "PostDominator";}

    public:
        PostDominator(BVDataPTAImpl* pt,
                        FunEntryICFGNode* fun_entry,
                        FunExitICFGNode* fun_exit): GenericDominatorTy(pt) {
            setEntryNode(fun_entry);
            setExitNode(fun_exit);
        }

        inline void setExitNode(FunExitICFGNode* fun_exit) {exit_node = fun_exit;}
        inline FunExitICFGNode* getExitNode() {return exit_node;}
};
    

#endif /* INCLUDE_PDOM_DOMINATORS_H_ */