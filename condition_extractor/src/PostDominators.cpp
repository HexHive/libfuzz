#include "PostDominators.h"

PostDominator::ICFGNodeSet PostDominator::behind(ICFGEdge* edge) {
    ICFGNodeSet nodes;

    // outs() << "1.a) Phi: " << sizePhi() << "\n";
    // outs() << "1.a) Phi Inv: " << sizePhiInv() << "\n";

    // edge is not in R
    if (C.find(edge) == C.end() ) {
        // src node == TAIL
        ICFGNode* tail_e = edge->getDstNode();
        nodes.insert(tail_e);
    }
    // edge is in R
    else {
        // src node == TAIL
        ICFGNode* tail_e = edge->getDstNode();
        nodes.insert(tail_e);

        // ICFGEdge* call_edge = phi_inv[(RetCFGEdge*)edge];
        ICFGEdge* call_edge = phi[(CallCFGEdge*)edge];

        ICFGNode* tail_e_inv = call_edge->getDstNode();
        nodes.insert(tail_e_inv);
    }

    return nodes;
}

void PostDominator::buildDom() {

    int tot_nodes = getTotRelevantNodes();

    ICFGNodeSet relevant_nodes = getRelevantNodes();
    FunExitICFGNode* exit_node = getExitNode();
    ICFG* icfg = getICFG();

    outs() << "[INFO] Building initial post-dom structure\n";

    // dominator of the start node is the start itself
    // Dom(n0) = {n0}
    // dom[exit_node].insert(exit_node);
    addDom(exit_node, exit_node);
    // dom[exit_node].insert(exit_node);

    int n_node = 0;
    double per_node;

    // for all other nodes, set all nodes as the dominators
    // for each n in N - {n0}
    for (auto node: relevant_nodes) {

        // ICFGNode* node = it->second;
        if (node == exit_node)
            continue;

        n_node++;

        // Dom(n) = N;
        setDom(node, relevant_nodes);

        per_node = ((double)n_node/(double)tot_nodes) * 100;
        outs() << "[DOING] " << n_node << "/" << tot_nodes << 
                    " (" << per_node  << ")% \r";
    }

    outs() << "\n";

    outs() << "[INFO] Running real post-dom computation\n";

    ICFGNodeSet curr_inter; 
    ICFGNodeSet all_doms_behind;
    ICFGNodeSet last_inter;
    ICFGNodeSet new_dom;

    int n_iteration = 1;

    bool debug = false;
    bool is_changed = true;
    // iteratively eliminate nodes that are not dominators
    // while changes in any Dom(n)
    while (is_changed) {
        is_changed = false;

        outs() << "[DOING] Iteration " << n_iteration << "\n";
        n_iteration++;

        n_node = 1;

        std::set<ICFGNode*>::reverse_iterator rit;

        // for each n in N - {n0}:
        for (rit = relevant_nodes.rbegin(); rit != relevant_nodes.rend(); rit++) {
            auto node = *rit;
        
            per_node = ((double)n_node/(double)tot_nodes) * 100;
            outs() << "[DOING] " << n_node << "/" << tot_nodes << 
                    " (" << per_node  << ")% \r";
            n_node++;

            // ICFGNode* node = it->second;
            if (node == exit_node)
                continue;    

            if (debug) {
                outs() << "1) Phi: " << sizePhi() << "\n";
                outs() << "1) Phi Inv: " << sizePhiInv() << "\n";
            }

            // outs() << (node->toString()) << "\n";

            // debug = node->getId() == 20;   

            if (node->hasOutgoingEdge()) {
                // ICFGNodeSet ahead_nodes;

                ICFGNode::const_iterator it2 = node->OutEdgeBegin();
                ICFGNode::const_iterator eit2 = node->OutEdgeEnd();

                bool first_intersect = true;

                for (; it2 != eit2; ++it2) {

                    for (auto n: behind(*it2)) {
                        ICFGNodeSet a_dom_set = getDom(n);

                        for (auto d: a_dom_set) 
                            if (isARelevantNode(d))
                                all_doms_behind.insert(d);
                        
                        a_dom_set.clear();
                    }

                    if (first_intersect) {
                        last_inter = all_doms_behind;
                        first_intersect = false;
                    } else {
                        // last_inter = all_doms_behind;
                        std::set_intersection(
                            last_inter.begin(), last_inter.end(),
                            all_doms_behind.begin(), all_doms_behind.end(), 
                            std::inserter(curr_inter, curr_inter.begin()));
                        std::swap(last_inter, curr_inter);
                        curr_inter.clear();

                    }

                    all_doms_behind.clear();
                }

                new_dom = last_inter;
                last_inter.clear();

                // if (debug) {
                //     outs() << "New Post-DOM:\n";
                //     for (auto n: new_dom)
                //         outs() << n->getId() << " ";
                //     outs() << "\n";
                // }

            }
            
            new_dom.insert(node);

            if (getDom(node) != new_dom) {
                clearDom(node);
                setDom(node, new_dom);
                is_changed = true;
            }

            if (debug) {
                outs() << "2) Phi: " << sizePhi() << "\n";
                outs() << "2) Phi Inv: " << sizePhiInv() << "\n";
            }

            new_dom.clear();
        }

        outs() << "\n";
    }

}
