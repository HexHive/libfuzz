#include "GenericDominatorTy.h"
#include "PhiFunction.h"

#include "SVF-FE/LLVMUtil.h"

// FLAVIO: I intentionally left the burned of creating the Dom relation in a
// separate function. I did not want to do everything in the constructor 
void GenericDominatorTy::createDom() {

    if (is_created) {
        outs() << "[ERROR] alrady created!\n";
        return;
    }

    outs() << "[INFO] Running pruneUnreachableFunctions()\n";
    this->pruneUnreachableFunctions();
    outs() << "[INFO] Running buildPhiFun()\n";
    this->buildPhiFun();
    outs() << "[INFO] Running inferSubGraph()\n";
    this->inferSubGraph();
    outs() << "[INFO] Running buildR()\n";
    this->buildR();
    outs() << "[INFO] Running buildDom()\n";
    this->buildDom();
    outs() << "[INFO] Running restoreUnreachableFunctions()\n";
    this->restoreUnreachableFunctions();

    is_created = true;

}

void GenericDominatorTy::restoreUnreachableFunctions() {
    // outs() << "[INFO] Restore eddges\n";
    for (auto edge: this->getDumpedEdge()) {
        // outs() << edge->toString() << "\n";
        edge->getDstNode()->addIncomingEdge(edge);
        edge->getSrcNode()->addOutgoingEdge(edge);
    }

    // UNCOMMENT FOR DEBUG
    // icfg->dump("icfg_restored");
}


void GenericDominatorTy::buildPhiFun() {

    SVFModule *svfModule = this->getModule();
    ICFG *icfg = this->getICFG();

    PHIFun phi;
    PHIFunInv phi_inv;

    getPhiFunction(svfModule, icfg, &phi, &phi_inv);    

    this->setPhi(phi);
    this->setPhiInv(phi_inv);

    // NOTE: to uncomment for debug
    // this->printPhiFunction();
    // this->printPhiInvFunction();
    // exit(1);

}

void GenericDominatorTy::buildR() {

    SVFModule *svfModule = this->getModule();
    ICFG* icfg = this->getICFG();

    SVF::SVFModule::llvm_iterator it = svfModule->llvmFunBegin();SVF::SVFModule::llvm_iterator eit = svfModule->llvmFunEnd();

    for (;it != eit; ++it) {
        const SVFFunction *fun = svfModule->getSVFFunction(*it);
        // outs() << fun->getName() << " [in DOM]\n";
        RetCFGEdge* ret_edge;
        CallCFGEdge* call_edge;
        ICFGNode::const_iterator it_fun_exit, eit_fun_exit;
        ICFGNode::const_iterator it_fun_entry, eit_fun_entry;

        FunExitICFGNode *fun_exit = icfg->getFunExitICFGNode(fun);
        FunEntryICFGNode *fun_entry = icfg->getFunEntryICFGNode(fun);

        if (fun_exit != nullptr) {
            // outs() << "fun_exit: " << fun_exit->toString() << "\n";
            
            it_fun_exit = fun_exit->OutEdgeBegin();
            eit_fun_exit = fun_exit->OutEdgeEnd();
            for (; it_fun_exit != eit_fun_exit; ++it_fun_exit) {
                // outs() << "it_fun_exit: " << (*it_fun_exit)->toString() << "\n";
                ret_edge = (RetCFGEdge*)(*it_fun_exit);
                
                this->addR(ret_edge);
            }
        }

        if (fun_entry != nullptr) {
            it_fun_entry = fun_entry->InEdgeBegin();
            eit_fun_entry = fun_entry->InEdgeEnd();
            for (; it_fun_entry != eit_fun_entry; ++it_fun_entry) {
                // outs() << "it_fun_exit: " << (*it_fun_exit)->toString() << "\n";
                call_edge = (CallCFGEdge*)(*it_fun_entry);
                
                this->addC(call_edge);
            }
        }

    }

    // NOTE: for debug
    // this->printR();
    // this->printC();
    // exit(1);
}

void GenericDominatorTy::pruneUnreachableFunctions() {

    assert(this->getEntryNode() && "We need an entry block!");

    const SVFFunction *main_fun = this->getEntryNode()->getFun();

    SVFModule *svfModule = this->getModule();
    PTACallGraph* callgraph = this->getPTACallGraph();

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

            FunEntryICFGNode *fun_entry = this->getICFG()->getFunEntryICFGNode(fun);
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
                        entry_called = this->getICFG()
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

                        exit_called = this->getICFG()->getFunExitICFGNode(fun_called);
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
                    this->addDumpedEdge(edge);
                }

                functions_done.insert(fun);
            }
        }
    }

    // this->getICFG()->dump("icfg_pruned");

    // outs() << "FUNCTIONS:\n";
    
    // for (auto f: functions_done)
    //     outs() << f->getName() << "\n";

    // outs() << "[END] Ends here for debug\n";
    // exit(1);
}


void GenericDominatorTy::inferSubGraph() {

    FunEntryICFGNode *entry_node = this->getEntryNode();

    assert(entry_node && "We need an entry block!");

    std::stack<ICFGNode*> working;
    std::set<ICFGNode*> visited;

    working.push(entry_node);

    while(!working.empty()) {

        ICFGNode *node = working.top();
        working.pop();

        if (node->hasOutgoingEdge()) {
            ICFGNode::const_iterator it = node->OutEdgeBegin();
            ICFGNode::const_iterator eit = node->OutEdgeEnd();
        
            for (; it != eit; ++it) {
                ICFGEdge *edge = *it;
                ICFGNode *dst = edge->getDstNode();

                if (visited.find(dst) != visited.end())
                    continue;
                
                if(auto ret_edge = SVFUtil::dyn_cast<RetCFGEdge>(edge)) {
                    visited.insert(dst);
                    working.push(dst);
                }
                else if(auto call_edge = SVFUtil::dyn_cast<CallCFGEdge>(edge)) {
                    ICFGEdge *next_ret = this->getPhi(call_edge);
                    ICFGNode *dst_r = next_ret->getDstNode();

                    ICFGNode *src = edge->getSrcNode();
                    bool is_call_indirect = false;
                    if (auto call_node = SVFUtil::dyn_cast<CallICFGNode>(src))
                        is_call_indirect = call_node->isIndirectCall();

                    if (is_call_indirect) {
                        working.push(dst_r);
                        visited.insert(dst_r);
                    } else {
                        working.push(dst);
                        working.push(dst_r);
                    }
                    visited.insert(dst);
                }
                 else {
                    working.push(dst);
                    visited.insert(dst);
                }
            }
        }

    }

    this->setRelevantNodes(visited);

    // outs() << "[INFO] Interesting nodes " << this->getTotRelevantNodes() << "\n";
    // ICFG* icfg = this->getICFG();
    // outs() << "[INFO] All nodes " << icfg->getTotalNodeNum() << "\n";
    // for (auto n: visited) {
    //     outs() << n->toString() << "\n";
    //     outs() << n->getNodeKind() << "\n";
    // }

    // outs() << "Exit for debug\n";
    // exit(1);
}

GenericDominatorTy::GenericDominatorTy(BVDataPTAImpl* a_point_to)
{
    point_to = a_point_to;

    PTACallGraph* callgraph = point_to->getPTACallGraph();
    // builder.updateCallGraph(callgraph);
    icfg = point_to->getICFG();
    icfg->updateCallGraph(callgraph);
    // icfg->dump("icfg_indirectcalls");
    // icfg = ander->getICFG();
}

bool GenericDominatorTy::dominates(ICFGNode *a, ICFGNode *b) {
    if (!is_created) {
        outs() << "[ERROR] " << getDomName() << " not created yet!\n";
        exit(1);
    }
    ICFGNodeSet dominators_b = getDom(b);
    return dominators_b.find(a) != dominators_b.end();
}

/*!
 * Dump DOMINATOR graph!
 */
void GenericDominatorTy::dumpTransRed(const std::string& file, bool simple)
{
    if (!is_created) {
        outs() << "[ERROR] " << getDomName() << " not created yet!\n";
        exit(1);
    }

    outs() << "[INFO] Dom covering " << getTotRelevantNodes() << "\n";
    outs() << "[INFO] Running transient reduction...\n";
    outs() << "[INFO] This might take a while..." 
            << "if too long, kill the process\n";

    buildTransientReduction();
    GraphPrinter::WriteGraphToFile(SVFUtil::outs(), file, this, simple);
}

void GenericDominatorTy::dumpDom(const std::string& file)
{
    if (!is_created) {
        outs() << "[ERROR] " << getDomName() << " not created yet!\n";
        exit(1);
    }

    outs() << "[INFO] Dom covering " << getTotRelevantNodes() << "\n";
    outs() << "[INFO] This might take a while..." 
            << "if too long, kill the process\n";

    ofstream dump_file;
    dump_file.open (file);
    for (auto d: relevant_nodes) {
        dump_file << d->getId() << " ";

        int n_dom = dom_v[d].size();
        int j = 0;

        for (auto n: dom_v[d]) {
            dump_file << n->getId();
            if (j < n_dom - 1)
                dump_file << " ";
            j++;
        }

        dump_file << "\n";
    }
    dump_file.close();

}

void GenericDominatorTy::loadDom(const std::string &file) {
    if (is_created) {
        outs() << "[ERROR] " << getDomName() << " is already created!\n";
        exit(1);
    }

    outs() << "[INFO] Loading " << file << "\n";
    outs() << "[INFO] This might take a while..." 
            << "if too long, kill the process\n";

    outs() << "[INFO] Running pruneUnreachableFunctions()\n";
    this->pruneUnreachableFunctions();
    outs() << "[INFO] Running buildPhiFun()\n";
    this->buildPhiFun();
    outs() << "[INFO] Running inferSubGraph()\n";
    this->inferSubGraph();
    outs() << "[INFO] Running buildR()\n";
    this->buildR();

    ifstream dump_file;
    dump_file.open (file);
    std::string line;
    while (std::getline(dump_file, line))
    {
        std::istringstream iss(line);
        int node_id;
        iss >> node_id;

        ICFGNode *node = this->getNode(node_id);

        while (iss >> node_id) {
            // outs() << "node_id " << node->getId() << "\n";
            // outs() << "dom_id " << node_id << "\n";
            // outs() << "before update: " << this->getDom(node).size() << "\n";
            this->addDom(node, this->getNode(node_id));
            // outs() << "after update: " << this->getDom(node).size() << "\n";
        }
    }
    dump_file.close();
    outs() << "[INFO] Dom loaded correctly\n";

    outs() << "[INFO] Running restoreUnreachableFunctions()\n";
    this->restoreUnreachableFunctions();

    is_created = true;
}

ICFGNode *GenericDominatorTy::getNode(int node_id) {

    for (auto node: getRelevantNodes()) {
        if (node->getId() == node_id)
            return node;
    }
    outs() << "[ERROR] Node " << node_id << " not found, abort!\n";
    exit(1);
    // return nullptr;
}

void GenericDominatorTy::buildTransientReduction() {

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
            nodeN1 = new DomNode(n1);
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
                    nodeN2 = new DomNode(n2);
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

void GenericDominatorTy::topoSort(int u, int *visited, 
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

int GenericDominatorTy::getLongestPath(int s, int d, int **reach, int V) {
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
void GenericDominatorTy::printR() {
    outs() << "[INFO] Print R\n";
    for (auto e: R) {
        outs() << e->toString() << "\n";
    }
    outs() << "[INFO] Print R (end)\n";
}

void GenericDominatorTy::printC() {
    outs() << "[INFO] Print C\n";
    for (auto e: C) {
        outs() << e->toString() << "\n";
    }
    outs() << "[INFO] Print C (end)\n";
}

void GenericDominatorTy::printPhiFunction() {
    outs() << "[INFO] Print PHI\n";
    for (auto el: phi) {
        outs() << "phi:\n";
        outs() << el.first->toString() << "\n";
        outs() << el.second->toString() << "\n";
        outs() << "\n";
    }
}
void GenericDominatorTy::printPhiInvFunction() {
    outs() << "[INFO] Print PHIInv\n";
    for (auto el: phi_inv) {
        outs() << "phi_inv:\n";
        outs() << el.first->toString() << "\n";
        outs() << el.second->toString() << "\n";
        outs() << "\n";
    }
}