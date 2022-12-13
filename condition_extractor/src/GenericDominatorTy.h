#ifndef INCLUDE_GENDOM_DOMINATORS_H_
#define INCLUDE_GENDOM_DOMINATORS_H_

#include <Graphs/ICFG.h>
#include <Graphs/SVFG.h>
#include <Graphs/GenericGraph.h>
#include "WPA/Andersen.h"

#include "PhiFunction.h"

using namespace SVF;
using namespace llvm;
using namespace std;

// class PostDominator;
class DomEdge;
class DomNode;

class GenericDominatorTy : public GenericGraph<DomNode,DomEdge> {
    public:
        typedef std::set<ICFGNode*> ICFGNodeSet;
        typedef std::set<ICFGEdge*> ICFGEdgeSet;
        typedef std::set<const SVFFunction*> SVFFunctionSet;
        typedef std::map<ICFGNode*, ICFGNodeSet> ICFGNodeMap;
        
    protected:
        ICFG* icfg;
        BVDataPTAImpl* point_to;
        FunEntryICFGNode* entry_node;
        // dom works for Dominator and
        ICFGNodeMap dom;
        // PHIFun: C -> R
        PHIFun phi;
        // PHIFunInv: R -> C
        PHIFunInv phi_inv;
        // R: return edge set
        ICFGEdgeSet R;
        // C: call edge set
        ICFGEdgeSet C;

        // dumped edges from alternative entry points
        ICFGEdgeSet dumped_edges;

        ICFGNodeSet relevant_nodes;

    public:
        GenericDominatorTy(BVDataPTAImpl*);
        bool dominates(ICFGNode*, ICFGNode*);

        /// Dump graph somehow
        void dumpTransRed(const std::string& file, bool simple = false);
        void dumpDom(const std::string& fil);

        inline FunEntryICFGNode* getEntryNode() {return entry_node;}
        inline void setEntryNode(FunEntryICFGNode* node) {entry_node = node;}
        inline BVDataPTAImpl* getPointToAnalysis() {return point_to;}
        inline SVFModule* getModule() {return point_to->getModule();}
        inline PTACallGraph* getPTACallGraph() {return point_to->getPTACallGraph();}
        inline ICFG* getICFG() {return icfg;}
        inline void addDumpedEdge(ICFGEdge* edge) {dumped_edges.insert(edge);}
        inline ICFGEdgeSet& getDumpedEdge() {return dumped_edges;}

        inline size_t sizePhi() {return phi.size();}
        inline size_t sizePhiInv() {return phi_inv.size();}

        inline void setPhi(PHIFun a_phi) {phi = a_phi;}
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
        inline void addC(CallCFGEdge* call_edge) {C.insert(call_edge);}

        // dom set/get
        inline void addDom(ICFGNode* node, ICFGNode* dom_node) {
            dom[node].insert(dom_node);
        }
        inline void setDom(ICFGNode* node, ICFGNodeSet dom_nodes) {
            dom[node] = dom_nodes;
        }
        inline void clearDom(ICFGNode* node) {dom[node].clear();}
        inline ICFGNodeSet& getDom(ICFGNode* node) {return dom[node];}

        virtual inline string getDomName() = 0;

    private:
        void buildTransientReduction();
        
        int getLongestPath(int, int, int**, int);
        void topoSort(int, int*, stack<int>&, int**, int); 

        // debug functions
        void printPhiFunction();
        void printPhiInvFunction();
        void printR();
        void printC();

        virtual void buildDom() = 0;

    public: // static!!
        static void createDom(GenericDominatorTy*);
        static void pruneUnreachableFunctions(GenericDominatorTy*);
        static void buildPhiFun(GenericDominatorTy*);
        static void inferSubGraph(GenericDominatorTy*);
        static void buildR(GenericDominatorTy*);
        static void restoreUnreachableFunctions(GenericDominatorTy*);
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
struct DOTGraphTraits<GenericDominatorTy*> : public DOTGraphTraits<ICFG*>
{

    typedef DomNode NodeType;
    DOTGraphTraits(bool isSimple = false) {
    }

    /// Return name of the graph
    static std::string getGraphName(GenericDominatorTy* d)
    {
        return d->getDomName();
    }

    std::string getNodeLabel(NodeType *node, GenericDominatorTy *graph)
    {
        return getSimpleNodeLabel(node, graph);
    }

    /// Return the label of an ICFG node
    static std::string getSimpleNodeLabel(NodeType *node, GenericDominatorTy*)
    {
        return node->toString();
    }

    static std::string getNodeAttributes(NodeType *node, GenericDominatorTy*)
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
    static std::string getEdgeAttributes(NodeType*, EdgeIter EI, 
        GenericDominatorTy*)
    {
        return "style=solid";
    }

    template<class EdgeIter>
    static std::string getEdgeSourceLabel(NodeType*, EdgeIter EI)
    {
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
struct GraphTraits<Inverse<DomNode *> > : 
    public GraphTraits<Inverse<SVF::GenericNode<DomNode,DomEdge>* > >
{
};

template<> struct GraphTraits<GenericDominatorTy*> :
    public GraphTraits<SVF::GenericGraph<DomNode,DomEdge>* >
{
    typedef DomNode *NodeRef;
};

} // End namespace llvm


#endif /* INCLUDE_GENDOM_DOMINATORS_H_ */