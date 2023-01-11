#include "Dominators.h"

Dominator::ICFGNodeSet Dominator::ahead(ICFGEdge* edge) {
    ICFGNodeSet nodes;

    // edge is not in R
    if (R.find(edge) == R.end() ) {
        // src node == HEAD
        ICFGNode* head_e = edge->getSrcNode();
        nodes.insert(head_e);
    }
    // edge is in R
    else {
        // src node == HEAD
        ICFGNode* head_e = edge->getSrcNode();
        nodes.insert(head_e);

        ICFGEdge* call_edge = phi_inv[(RetCFGEdge*)edge];
        ICFGNode* head_e_inv = call_edge->getSrcNode();
        nodes.insert(head_e_inv);
    }

    return nodes;
}

void Dominator::buildDom() {

    int tot_nodes = getTotRelevantNodes();

    ICFGNodeSet relevant_nodes = getRelevantNodes();
    FunEntryICFGNode* entry_node = getEntryNode();
    ICFG* icfg = getICFG();

    outs() << "[INFO] Building initial dom structure\n";

    // dominator of the start node is the start itself
    // Dom(n0) = {n0}
    // dom[entry_node].insert(entry_node);
    addDom(entry_node, entry_node);
    // dom[entry_node].insert(entry_node);

    int n_node = 0;
    double per_node;

    // for all other nodes, set all nodes as the dominators
    // for each n in N - {n0}
    for (auto node: relevant_nodes) {

        // ICFGNode* node = it->second;
        if (node == entry_node)
            continue;

        n_node++;

        // Dom(n) = N;
        setDom(node, relevant_nodes);

        per_node = ((double)n_node/(double)tot_nodes) * 100;
        outs() << "[DOING] " << n_node << "/" << tot_nodes << 
                    " (" << per_node  << ")% \r";
    }

    outs() << "\n";

    outs() << "[INFO] Running real dom computation\n";

    ICFGNodeSet curr_inter; 
    ICFGNodeSet all_doms_ahead;
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

        // for each n in N - {n0}:
        // for (ICFG::iterator it = icfg->begin(); it != icfg->end(); it++) {
        for (auto node: relevant_nodes) {

            per_node = ((double)n_node/(double)tot_nodes) * 100;
            outs() << "[DOING] " << n_node << "/" << tot_nodes << 
                    " (" << per_node  << ")% \r";
            n_node++;

            // ICFGNode* node = it->second;
            if (node == entry_node)
                continue;    

            // outs() << (node->toString()) << "\n";

            // debug = node->getId() == 18;   

            if (debug) {
                outs() << "Old DOM:\n";
                for (auto n: getDom(node))
                    outs() << n->getId() << " ";
                outs() << "\n";
                outs() << "Incoming edges: " << node->hasIncomingEdge() << "\n";
                outs() << "\n";
            }

            if (node->hasIncomingEdge()) {
                // ICFGNodeSet ahead_nodes;

                ICFGNode::const_iterator it2 = node->InEdgeBegin();
                ICFGNode::const_iterator eit2 = node->InEdgeEnd();

                bool first_intersect = true;

                for (; it2 != eit2; ++it2) {

                    // ICFGNode *ahead_node;

                    for (auto n: ahead(*it2)) {
                        ICFGNodeSet a_dom_set = getDom(n);

                        for (auto d: a_dom_set) 
                            if (isARelevantNode(d))
                                all_doms_ahead.insert(d);
                        
                        a_dom_set.clear();
                    }

                    if (debug) {
                        ICFGEdge* edge = *it2;
                        outs() << "parent:\n";
                        edge->getSrcNode()->dump();
                        outs() << "all_doms_ahead\n";
                        for (auto n: all_doms_ahead)
                            outs() << n->getId() << " ";
                        outs() << "\n";
                    }

                    if (first_intersect) {
                        last_inter = all_doms_ahead;
                        first_intersect = false;
                    } else {
                        // last_inter = all_doms_ahead;
                        std::set_intersection(
                            last_inter.begin(), last_inter.end(),
                            all_doms_ahead.begin(), all_doms_ahead.end(), 
                            std::inserter(curr_inter, curr_inter.begin()));
                        std::swap(last_inter, curr_inter);
                        curr_inter.clear();

                    }

                    all_doms_ahead.clear();
                }

                new_dom = last_inter;
                last_inter.clear();

                if (debug) {
                    outs() << "New DOM:\n";
                    for (auto n: new_dom)
                        outs() << n->getId() << " ";
                    outs() << "\n";
                }

            }
            
            new_dom.insert(node);

            if (getDom(node) != new_dom) {
                clearDom(node);
                setDom(node, new_dom);
                is_changed = true;
            }

            new_dom.clear();
        }

        outs() << "\n";
    }
}