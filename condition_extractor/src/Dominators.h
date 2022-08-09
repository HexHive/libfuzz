
#ifndef INCLUDE_DOM_DOMINATORS_H_
#define INCLUDE_DOM_DOMINATORS_H_

#include <Graphs/ICFG.h>
#include <Graphs/SVFG.h>
#include <Graphs/GenericGraph.h>
#include "WPA/Andersen.h"

#include "PhiFunction.h"

using namespace SVF;
using namespace llvm;
using namespace std;

class Dominator;
class DomEdge;
class DomNode;

typedef GenericGraph<DomNode,DomEdge> GenericDominatorTy;
class Dominator : public GenericDominatorTy {
    public:
        typedef std::set<ICFGNode*> ICFGNodeSet;
        typedef std::set<ICFGEdge*> ICFGEdgeSet;
        typedef std::set<const SVFFunction*> SVFFunctionSet;
        typedef std::map<ICFGNode*, ICFGNodeSet> ICFGNodeMap;
        
    private:
        ICFG* icfg;
        Andersen* ander;
        FunEntryICFGNode* entry_node;
        ICFGNodeMap dom;
        // PHIFun: C -> R
        PHIFun phi;
        // PHIFunInv: R -> C
        PHIFunInv phi_inv;
        // R: return edge set
        ICFGEdgeSet R;

        // dumped edges from alternative entry points
        ICFGEdgeSet dumped_edges;

        ICFGNodeSet relevant_nodes;

    public:
        Dominator(Andersen*, FunEntryICFGNode*);
        bool dominates(ICFGNode*, ICFGNode*);

        /// Dump graph somehow
        void dumpTransRed(const std::string& file, bool simple = false);
        void dumpDom(const std::string& fil);

        inline FunEntryICFGNode* getEntryNode() {return entry_node;}
        inline Andersen* getPointToAnalysis() {return ander;}
        inline SVFModule* getModule() {return ander->getModule();}
        inline PTACallGraph* getPTACallGraph() {return ander->getPTACallGraph();}
        inline ICFG* getICFG() {return icfg;}
        inline void addDumpedEdge(ICFGEdge* edge) {dumped_edges.insert(edge);}
        inline ICFGEdgeSet& getDumpedEdge() {return dumped_edges;}

        inline void setPhi(PHIFun a_phi) {
            phi = a_phi;
        }
        inline RetCFGEdge* getPhi(CallCFGEdge* call_edge) {
            return phi[call_edge];
        }
        inline void setPhiInv(PHIFunInv a_phi_inv) {
            phi_inv = a_phi_inv;
        }
        inline CallCFGEdge* getPhiInv(RetCFGEdge* ret_edge) {
            return phi_inv[ret_edge];
        }

        inline void setRelevantNodes(ICFGNodeSet nodes)
        {relevant_nodes = nodes;}
        inline unsigned int getTotRelevantNodes() {
            return relevant_nodes.size();
        }
        inline bool isARelevantNode(ICFGNode* node) {
            return relevant_nodes.find(node) != relevant_nodes.end();
        }
        inline ICFGNodeSet& getRelevantNodes() {return relevant_nodes;}

        inline void addR(RetCFGEdge* ret_edge) {R.insert(ret_edge);}

        inline void addDom(ICFGNode* node, ICFGNode* dom_node) {
            dom[node].insert(dom_node);
        }
        inline void setDom(ICFGNode* node, ICFGNodeSet dom_nodes) {
            dom[node] = dom_nodes;
        }
        inline void clearDom(ICFGNode* node) {dom[node].clear();}
        inline ICFGNodeSet& getDom(ICFGNode* node) {return dom[node];}

    private:
        void buildTransientReduction();

        ICFGNodeSet ahead(ICFGEdge*);
        int getLongestPath(int, int, int**, int);
        void topoSort(int, int*, stack<int>&, int**, int); 

        // debug functions
        void printPhiFunction();
        void printPhiInvFunction();
        void printR();

    public: // static!!
        static Dominator* createDom(Andersen*, FunEntryICFGNode*);
        static void pruneUnreachableFunctions(Dominator*);
        static void buildPhiFun(Dominator*);
        static void inferSubGraph(Dominator*);
        static void buildR(Dominator*);
        static void buildDom(Dominator*);
        static void restoreUnreachableFunctions(Dominator*);
};


typedef GenericEdge<DomNode> DomEdgeTy;
class DomEdge : public DomEdgeTy {

public:
    /// Constructor
    DomEdge(DomNode* s, DomNode* d) : DomEdgeTy(s,d,0)
    {
    }

    typedef GenericNode<DomNode,DomEdge>::GEdgeSetTy DomEdgeSetTy;
    typedef DomEdgeSetTy SVFGEdgeSetTy;
};

typedef GenericNode<DomNode, DomEdge> DomNodeTy;
class DomNode : public DomNodeTy {

public:
    /// 1 kinds of Dom node
    enum DomNodeK
    {
        DomeNode
    };

public:
     /// Constructor
    DomNode(NodeID i) : DomNodeTy(i, DomNodeK::DomeNode)
    {
        node = nullptr;
    }

    void setICFGNode(ICFGNode *n) {
        node = n;
    }    

    ICFGNode* getICFGNode() {
        return node;
    }

    const std::string toString() const
    {
        if (node == nullptr) {
            std::string str;
            raw_string_ostream rawstr(str);
            rawstr << "DomNode " << getId();
            return rawstr.str();
        }

        return node->toString();
    }
private:
    ICFGNode *node;
};

namespace llvm
{
template<>
struct DOTGraphTraits<Dominator*> : public DOTGraphTraits<ICFG*>
{

    typedef DomNode NodeType;
    DOTGraphTraits(bool isSimple = false) {
    }

    /// Return name of the graph
    static std::string getGraphName(Dominator*)
    {
        return "Dominator";
    }

    std::string getNodeLabel(NodeType *node, Dominator *graph)
    {
        return getSimpleNodeLabel(node, graph);
    }

    /// Return the label of an ICFG node
    static std::string getSimpleNodeLabel(NodeType *node, Dominator*)
    {
        return node->toString();
    }

    static std::string getNodeAttributes(NodeType *node, Dominator*)
    {
        if (node == nullptr) {
            std::string str;
            raw_string_ostream rawstr(str);
            rawstr <<  "color=black";
            return rawstr.str();
        }

        std::string str;
        raw_string_ostream rawstr(str);

        ICFGNode *in_node = node->getICFGNode();

        if(SVFUtil::isa<IntraICFGNode>(in_node))
        {
            rawstr <<  "color=black";
        }
        else if(SVFUtil::isa<FunEntryICFGNode>(in_node))
        {
            rawstr <<  "color=yellow";
        }
        else if(SVFUtil::isa<FunExitICFGNode>(in_node))
        {
            rawstr <<  "color=green";
        }
        else if(SVFUtil::isa<CallICFGNode>(in_node))
        {
            rawstr <<  "color=red";
        }
        else if(SVFUtil::isa<RetICFGNode>(in_node))
        {
            rawstr <<  "color=blue";
        }
        else if(SVFUtil::isa<GlobalICFGNode>(in_node))
        {
            rawstr <<  "color=purple";
        }
        else
            assert(false && "no such kind of node!!");

        rawstr <<  "";

        return rawstr.str();
    }

    template<class EdgeIter>
    static std::string getEdgeAttributes(NodeType*, EdgeIter EI, Dominator*)
    {
        // ICFGEdge* edge = *(EI.getCurrent());
        // assert(edge && "No edge found!!");
        // if (SVFUtil::isa<CallCFGEdge>(edge))
        //     return "style=solid,color=red";
        // else if (SVFUtil::isa<RetCFGEdge>(edge))
        //     return "style=solid,color=blue";
        // else
        //     return "style=solid";
        // return "";

        return "style=solid";
    }

    template<class EdgeIter>
    static std::string getEdgeSourceLabel(NodeType*, EdgeIter EI)
    {
        // ICFGEdge* edge = *(EI.getCurrent());
        // assert(edge && "No edge found!!");

        // std::string str;
        // raw_string_ostream rawstr(str);
        // if (CallCFGEdge* dirCall = SVFUtil::dyn_cast<CallCFGEdge>(edge))
        //     rawstr << dirCall->getCallSite();
        // else if (RetCFGEdge* dirRet = SVFUtil::dyn_cast<RetCFGEdge>(edge))
        //     rawstr << dirRet->getCallSite();

        // return rawstr.str();
        return "";
    }
};
} // End namespace llvm

namespace llvm
{
/* !
 * GraphTraits specializations for generic graph algorithms.
 * Provide graph traits for traversing from a constraint node using standard graph traversals.
 */
template<> struct GraphTraits<DomNode*> : public GraphTraits<SVF::GenericNode<DomNode,DomEdge>*  >
{
};

/// Inverse GraphTraits specializations for call graph node, it is used for inverse traversal.
template<>
struct GraphTraits<Inverse<DomNode *> > : public GraphTraits<Inverse<SVF::GenericNode<DomNode,DomEdge>* > >
{
};

template<> struct GraphTraits<Dominator*> : public GraphTraits<SVF::GenericGraph<DomNode,DomEdge>* >
{
    typedef DomNode *NodeRef;
};

} // End namespace llvm

#endif /* INCLUDE_DOM_DOMINATORS_H_ */