#include "Dominators.h"
#include "PhiFunction.h"

#include "SVF-FE/LLVMUtil.h"

Dominator* Dominator::createDom(Andersen *ander, FunEntryICFGNode *entry_node) {
    
    Dominator *dom = new Dominator(ander, entry_node);

    outs() << "[INFO] Running pruneUnreachableFunctions()\n";
    pruneUnreachableFunctions(dom);
    outs() << "[INFO] Running buildPhiFun()\n";
    buildPhiFun(dom);
    outs() << "[INFO] Running inferSubGraph()\n";
    inferSubGraph(dom);
    outs() << "[INFO] Running buildR()\n";
    buildR(dom);
    outs() << "[INFO] Running buildDom()\n";
    buildDom(dom);
    // outs() << "[INFO] Running restoreUnreachableFunctions()\n";
    // restoreUnreachableFunctions(dom);

    return dom;

}

Dominator::Dominator(Andersen* a_ander, FunEntryICFGNode* a_entry_node) {

    ander = a_ander;
    entry_node = a_entry_node;

    PTACallGraph* callgraph = ander->getPTACallGraph();
    // builder.updateCallGraph(callgraph);
    icfg = ander->getICFG();
    icfg->updateCallGraph(callgraph);
    // icfg->dump("icfg_indirectcalls");
    // icfg = ander->getICFG();
}

bool Dominator::dominates(ICFGNode *a, ICFGNode *b) {
    ICFGNodeSet dominators_b = getDom(b);
    return dominators_b.find(a) != dominators_b.end();
}

/*!
 * Dump ICFG
 */
void Dominator::dumpTransRed(const std::string& file, bool simple)
{
    outs() << "[INFO] Dom covering " << getTotRelevantNodes() << "\n";
    outs() << "[INFO] Running transient reduction...\n";
    outs() << "[INFO] This might thake a while..." 
            << "if too long, kill the process\n";

    buildTransientReduction();
    GraphPrinter::WriteGraphToFile(SVFUtil::outs(), file, this, simple);
}

void Dominator::dumpDom(const std::string& file) {
    outs() << "[INFO] Dom covering " << getTotRelevantNodes() << "\n";
    outs() << "[INFO] This might thake a while..." 
            << "if too long, kill the process\n";

    ofstream dump_file;
    dump_file.open (file + ".txt");
    for (auto d: relevant_nodes) {
        dump_file << "{ \"NodeID\": " << d->getId() << ", \"Domniators\": [";

        int n_dom = dom[d].size();
        int j = 0;

        for (auto n: dom[d]) {
            dump_file << n->getId();
            if (j < n_dom - 1)
                dump_file << ", ";
            j++;
        }

        dump_file << " ] }\n";
    }
    dump_file.close();

}

void Dominator::pruneUnreachableFunctions(Dominator *dom) {

    assert(dom->getEntryNode() && "We need an entry block!");

    const SVFFunction *main_fun = dom->getEntryNode()->getFun();

    SVFModule *svfModule = dom->getModule();
    PTACallGraph* callgraph = dom->getPTACallGraph();

    SVF::SVFModule::llvm_iterator it, eit;

    SVFFunctionSet functions_done;

    bool uncalled_functions = true;
    while (uncalled_functions) {

        uncalled_functions = false;
        
        it = svfModule->llvmFunBegin();
        eit = svfModule->llvmFunEnd();

        for (;it != eit; ++it) {
            const SVFFunction *fun = svfModule->getSVFFunction(*it);

            ICFGEdgeSet tmp_dumped_edges;

            // outs() << "Fun: " << fun->getName() << "\n";

            if (fun == main_fun) {
                // outs() << "skip it\n";
                continue;
            }

            if (functions_done.find(fun) != functions_done.end())
                continue;

            FunEntryICFGNode *fun_entry = dom->getICFG()->getFunEntryICFGNode(fun);
            FunEntryICFGNode *entry_called;
            FunExitICFGNode *exit_called;
            PTACallGraphNode *node_callee, *node_called;

            if (!fun_entry->hasIncomingEdge()) {
                uncalled_functions = true;

                // outs() << "Has not incoming edges\n";
                node_callee = callgraph->getCallGraphNode(fun);

                if (node_callee->hasOutgoingEdge()) {
                    // outs() << "Has outgoing edges\n";

                    PTACallGraphNode::const_iterator it2, eit2;
                    it2 = node_callee->OutEdgeBegin();
                    eit2 = node_callee->OutEdgeEnd();

                    for (; it2 != eit2; ++it2) {
                        node_called = (*it2)->getDstNode();        
                        auto const fun_called = node_called->getFunction();

                        // outs() << fun_called->getName() << "\n";

                        ICFGEdge *edge_to_remove = nullptr;

                        // have to select the callee node in ICFG, before it was
                        // the calle in CF
                        entry_called = dom->getICFG()
                                        ->getFunEntryICFGNode(fun_called);
                        ICFGNode::const_iterator it3 = 
                                        entry_called->InEdgeBegin();
                        ICFGNode::const_iterator eit3 = 
                                        entry_called->InEdgeEnd();
                        if (entry_called->hasIncomingEdge()) {
                            for (; it3 != eit3; ++it3) {
                                ICFGNode *src = (*it3)->getSrcNode();
                                if (src->getFun() == fun) {
                                    edge_to_remove = *it3;
                                    break;
                                }
                            }

                            assert(edge_to_remove &&
                                    "The call edge to remove is not found!");

                            tmp_dumped_edges.insert(edge_to_remove);
                        }

                        exit_called = dom->getICFG()->getFunExitICFGNode(fun_called);
                        if (exit_called->hasOutgoingEdge()) {
                            edge_to_remove = nullptr;
                            it3 = exit_called->OutEdgeBegin();
                            eit3 = exit_called->OutEdgeEnd();
                            for (; it3 != eit3; ++it3) {
                                ICFGNode *dst = (*it3)->getDstNode();
                                if (dst->getFun() == fun) {
                                    edge_to_remove = *it3;
                                    break;
                                }
                            }

                            assert(edge_to_remove && 
                                    "The return edge to remove is not found!");

                            tmp_dumped_edges.insert(edge_to_remove);
                        }
                    }

                }

                // outs() << "[INFO] Edges to remove (tmp)\n";
                for (auto edge: tmp_dumped_edges) {
                    // outs() << edge->toString() << "\n";
                    edge->getDstNode()->removeIncomingEdge(edge);
                    edge->getSrcNode()->removeOutgoingEdge(edge);
                    // dumped_edges.insert(edge);
                    dom->addDumpedEdge(edge);
                }

                functions_done.insert(fun);
            }
        }
    }

    // icfg->dump("icfg_pruned");

    // outs() << "FUNCTIONS:\n";
    
    // for (auto f: functions_done)
    //     outs() << f->getName() << "\n";

    // outs() << "[END] Ends here for debug\n";
    // exit(1);
}

void Dominator::restoreUnreachableFunctions(Dominator* dom) {
    // outs() << "[INFO] Restore eddges\n";
    for (auto edge: dom->getDumpedEdge()) {
        // outs() << edge->toString() << "\n";
        edge->getDstNode()->addIncomingEdge(edge);
        edge->getSrcNode()->addOutgoingEdge(edge);
    }


    // icfg->dump("icfg_restored");
}

void Dominator::buildPhiFun(Dominator *dom) {

    SVFModule *svfModule = dom->getModule();
    ICFG *icfg = dom->getICFG();

    PHIFun phi;
    PHIFunInv phi_inv;

    getPhiFunction(svfModule, icfg, &phi, &phi_inv);    

    dom->setPhi(phi);
    dom->setPhiInv(phi_inv);

    // NOTE: to uncomment for debug
    // printPhiFunction();
    // printPhiInvFunction();

}

void Dominator::buildR(Dominator* dom) {

    SVFModule *svfModule = dom->getModule();
    ICFG* icfg = dom->getICFG();

    SVF::SVFModule::llvm_iterator it = svfModule->llvmFunBegin();SVF::SVFModule::llvm_iterator eit = svfModule->llvmFunEnd();

    for (;it != eit; ++it) {
        const SVFFunction *fun = svfModule->getSVFFunction(*it);
        // outs() << fun->getName() << " [in DOM]\n";
        RetCFGEdge* ret_edge;
        ICFGNode::const_iterator it_fun_exit, eit_fun_exit;

        FunExitICFGNode *fun_exit = icfg->getFunExitICFGNode(fun);

        if (fun_exit == nullptr)
            continue;

        // outs() << "fun_exit: " << fun_exit->toString() << "\n";
        
        it_fun_exit = fun_exit->OutEdgeBegin();
        eit_fun_exit = fun_exit->OutEdgeEnd();
        for (; it_fun_exit != eit_fun_exit; ++it_fun_exit) {
            // outs() << "it_fun_exit: " << (*it_fun_exit)->toString() << "\n";
            ret_edge = (RetCFGEdge*)(*it_fun_exit);
            
            dom->addR(ret_edge);
        }

    }

    // NOTE: for debug
    // printR();
    // exit(1);
}

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

void Dominator::inferSubGraph(Dominator *dom) {

    FunEntryICFGNode *entry_node = dom->getEntryNode();

    assert(entry_node && "We need an entry block!");

    std::stack<std::pair<ICFGNode*,std::stack<ICFGEdge*>>> working;

    std::set<ICFGNode*> visited;

    std::stack<ICFGEdge*> empty_stack;
    working.push(std::make_pair(entry_node, empty_stack));

    while(!working.empty()) {

        auto el = working.top();
        working.pop();

        ICFGNode *node = el.first;
        std::stack<ICFGEdge*> curr_stack = el.second;

        if (node->hasOutgoingEdge()) {
            ICFGNode::const_iterator it = node->OutEdgeBegin();
            ICFGNode::const_iterator eit = node->OutEdgeEnd();
        
            for (; it != eit; ++it) {
                ICFGEdge *edge = *it;
                ICFGNode *dst = edge->getDstNode();

                if (visited.find(dst) != visited.end()) 
                    continue;
                
                if(auto ret_edge = SVFUtil::dyn_cast<RetCFGEdge>(edge)) {

                    if (curr_stack.size() != 0) {
                        ICFGEdge *ret = curr_stack.top();
                        if (ret_edge == ret) {
                            curr_stack.pop();
                            working.push(std::make_pair(dst, curr_stack));
                            visited.insert(dst);
                        }
                    }
                }
                else if(auto call_edge = SVFUtil::dyn_cast<CallCFGEdge>(edge)) {
                    ICFGEdge *next_ret = dom->getPhi(call_edge);
                    curr_stack.push(next_ret);
                    working.push(std::make_pair(dst, curr_stack));
                    visited.insert(dst);
                }
                 else {
                    working.push(std::make_pair(dst, curr_stack));
                    visited.insert(dst);
                }
            }
        }

    }

    dom->setRelevantNodes(visited);

    outs() << "[INFO] Interesting nodes " << dom->getTotRelevantNodes() << "\n";
    ICFG* icfg = dom->getICFG();
    outs() << "[INFO] All nodes " << icfg->getTotalNodeNum() << "\n";
    // for (auto n: visited)
    //     outs() << n->toString() << "\n";

    // outs() << "Exit for debug\n";
    // exit(1);
}

void Dominator::buildDom(Dominator* dom) {

    // int tot_nodes =  icfg->getTotalNodeNum();
    int tot_nodes = dom->getTotRelevantNodes();

    ICFGNodeSet relevant_nodes = dom->getRelevantNodes();
    FunEntryICFGNode* entry_node = dom->getEntryNode();
    ICFG* icfg = dom->getICFG();

    outs() << "[INFO] Building initial dom structure\n";

    // dominator of the start node is the start itself
    // Dom(n0) = {n0}
    // dom[entry_node].insert(entry_node);
    dom->addDom(entry_node, entry_node);
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
        dom->setDom(node, relevant_nodes);

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

    bool debug = false;
    bool is_changed = true;
    // iteratively eliminate nodes that are not dominators
    // while changes in any Dom(n)
    while (is_changed) {
        is_changed = false;

        // for each n in N - {n0}:
        // for (ICFG::iterator it = icfg->begin(); it != icfg->end(); it++) {
        for (auto node: relevant_nodes) {
            // ICFGNode* node = it->second;
            if (node == entry_node)
                continue;    

            // outs() << (node->toString()) << "\n";

            // debug = node->getId() == 20;   

            if (node->hasIncomingEdge()) {
                // ICFGNodeSet ahead_nodes;

                ICFGNode::const_iterator it2 = node->InEdgeBegin();
                ICFGNode::const_iterator eit2 = node->InEdgeEnd();

                bool first_intersect = true;

                for (; it2 != eit2; ++it2) {

                    // ICFGNode *ahead_node;

                    for (auto n: dom->ahead(*it2)) {
                        ICFGNodeSet a_dom_set = dom->getDom(n);

                        for (auto d: a_dom_set) 
                            if (dom->isARelevantNode(d))
                                all_doms_ahead.insert(d);
                        
                        a_dom_set.clear();
                    }

                    if (first_intersect) {
                        last_inter = all_doms_ahead;
                        first_intersect = false;
                    } else {
                        // last_inter = all_doms_ahead;
                        std::set_intersection(last_inter.begin(), last_inter.end(),
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

            if (dom->getDom(node) != new_dom) {
                dom->clearDom(node);
                dom->setDom(node, new_dom);
                is_changed = true;
            }

            new_dom.clear();
        }
    }
}

void Dominator::buildTransientReduction() {

    // first, I need a map between int and NodeID
    std::map<int, ICFGNode*> idNodeMap;

    int V = 0; // number of nodes
    // for (auto n: dom) {
    for (auto node: relevant_nodes) {
        idNodeMap[V] = node;
        V++;
    }

    /* reach[][] will be the output matrix
    // that will finally have the
       shortest distances between
       every pair of vertices */
    int **reach, **tran_red; 
    int i, j, k;
    reach = (int**)malloc(sizeof(int*) * V);
    tran_red = (int**)malloc(sizeof(int*) * V);
    for (i = 0; i < V; i++) {
        reach[i] = (int*)malloc(sizeof(int) * V);
        tran_red[i] = (int*)malloc(sizeof(int) * V);
    }
    ICFGNode *node_i, *node_j;

    /* Initialize the solution matrix same
    as input graph matrix. Or
       we can say the initial values of
       shortest distances are based
       on shortest paths considering
       no intermediate vertex. */
    for (i = 0; i < V; i++)
        for (j = 0; j < V; j++) {
            if (i != j) {
                node_i = idNodeMap[i];
                node_j = idNodeMap[j];
                reach[i][j] = dominates(node_i, node_j);
            } else {
                reach[i][j] = 0;
            }
        }    

    // Print the shortest distance matrix
    // outs() << "Following matrix is the initial graph\n";
    // for (i = 0; i < V; i++)
    // {
    //     outs() << idNodeMap[i]->getId() << " -> ";
    //     for (int j = 0; j < V; j++)
    //         if (reach[i][j])
    //             outs() << idNodeMap[j]->getId() << " ";
    //             // outs() << reach[i][j] << " ";
    //     // outs() << "\n";
    // }
    // // outs() << "\n";

    // finding longset paths for each node
    for (i = 0; i < V; i++) {
        for (j = 0; j < V; j++) { 
            if (getLongestPath(i, j, reach, V) == 1)
                tran_red[i][j] = 1;
            else 
                tran_red[i][j] = 0;
        }
    }

    DomNode *nodeN1, *nodeN2;

    // Print the shortest distance matrix
    // outs() << "Shortest node for the longest path\n";
    for (i = 0; i < V; i++)
    {
        auto n1 = idNodeMap[i];
        auto n1_id = n1->getId();

        if (hasGNode(n1_id)) {
            nodeN1 = getGNode(n1_id);
        }
        else {
            nodeN1 = new DomNode(n1_id);
            nodeN1->setICFGNode(n1);
            addGNode(n1_id, nodeN1);
        }

        // outs() << n1_id << " -> ";
        for (int j = 0; j < V; j++)
            if (tran_red[i][j]) {

                auto n2 = idNodeMap[j];
                auto n2_id = n2->getId();

                // outs() << n2_id << " ";
                
                if (hasGNode(n2_id)) {
                    nodeN2 = getGNode(n2_id);
                }
                else {
                    nodeN2 = new DomNode(n2_id);
                    nodeN2->setICFGNode(n2);
                    addGNode(n2_id, nodeN2);
                }

                DomEdge* edge = new DomEdge(nodeN1,nodeN2);
                edge->getDstNode()->addIncomingEdge(edge);
                edge->getSrcNode()->addOutgoingEdge(edge);

            }
        // outs() << "\n";

    }
    // outs() << "\n";
 

    // always clean your dirty room!!
    for (i = 0; i < V; i++) {
        free(reach[i]);
        free(tran_red[i]);
    }
    free(reach);
    free(tran_red);
}

void Dominator::topoSort(int u, int *visited, 
                        stack<int>&stack, int **reach, int V) {
    visited[u] = 1;    //set as the node v is visited

    for(int v = 0; v < V; v++) {
        //for allvertices v adjacent to u
        if(reach[u][v]) {
            if(!visited[v])
                topoSort(v, visited, stack, reach, V);
        }
    }

    //push starting vertex into the stack
    stack.push(u);
}

int Dominator::getLongestPath(int s, int d, int **reach, int V) {
    if (s < 0 || d < 0 || s >= V || d >= V)
        return -1;

    int *dist = (int*)malloc(sizeof(int) * V);
    memset(dist, 0, sizeof(int) * V);
    
    std::stack<int> stack;
    int *vis = (int*)malloc(sizeof(int) * V);
    memset(vis, 0, sizeof(int) * V);

    for(int i = 0; i< V; i++)
        vis[i] = 0;    // make all nodes as unvisited at first
            
    for(int i = 0; i< V; i++)    //perform topological sort for vertices
        if(!vis[i])
            topoSort(i, vis, stack, reach, V);
                
    for(int i = 0; i< V; i++)
        dist[i] = -1;    //initially all distances are infinity
    dist[s] = 0;    //distance for start vertex is 0
    
    //when stack contains element, process in topological order
    while(!stack.empty()) {
        int nextVert = stack.top(); stack.pop();

        if(dist[nextVert] != -1) {
            for(int v = 0; v < V; v++) {
                if(reach[nextVert][v]) {
                    if(dist[v] < dist[nextVert] + 1)
                        dist[v] = dist[nextVert] + 1;
                }
            }
        }
    }

    int longest_path = dist[d];

    free(dist);
    free(vis);

    return longest_path;
}

/* DEBUG UTILITIES */
void Dominator::printR() {
    outs() << "[INFO] Print R\n";
    for (auto e: R) {
        outs() << e->toString() << "\n";
    }
    outs() << "[INFO] Print R (end)\n";
}

void Dominator::printPhiFunction() {
    outs() << "[INFO] Print PHI\n";
    for (auto el: phi) {
        outs() << "phi:\n";
        outs() << el.first->toString() << "\n";
        outs() << el.second->toString() << "\n";
        outs() << "\n";
    }
}
void Dominator::printPhiInvFunction() {
    outs() << "[INFO] Print PHIInv\n";
    for (auto el: phi_inv) {
        outs() << "phi_inv:\n";
        outs() << el.first->toString() << "\n";
        outs() << el.second->toString() << "\n";
        outs() << "\n";
    }
}