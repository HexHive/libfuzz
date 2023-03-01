#include "AccessType.h"
#include "AccessTypeHandler.h"

#include "SVF-FE/LLVMUtil.h"

#define MAX_STACKSIZE 20

// static fields, mainly for debug
bool ValueMetadata::debug = false;
std::string ValueMetadata::debug_condition = "";
bool ValueMetadata::consider_indirect_calls = false;


// NOT EXPOSED FUNCTIONS -- THESE FUNCTIONS ARE MEANT FOR ONLY INTERNAL USAGE!
bool areConnected(const VFGNode*, const VFGNode*);
std::set<const VFGNode*> getDefinitionSet(const VFGNode*);
bool areCompatible(FunctionType*,FunctionType*);
bool predefinedAccessTypeDispatcher(ValueMetadata*, std::string fun,
    const VFGNode*, AccessType);
// NOT EXPOSED FUNCTIONS -- END!

/**
If exists, call the predefined handler for function fun.

@param: ats: the access type set to be updated by the handler
@param: fun: the name of the function
@param: node: the node currently analyzed

@return: boolean value indicating if the analysis should continue on the subfield.
         For example, it might be false for a cast to indicate we do not try to follow further child of the node.
         default true.
*/
bool predefinedAccessTypeDispatcher(ValueMetadata *mdata,
    std::string fun, const VFGNode * node, AccessType at) {
    // TODO move this line to the .h file
    auto pos = accessTypeHandlers.find(fun);
    if (pos != accessTypeHandlers.end()) {
        // call the specific handler
        return pos->second(mdata, fun, node, at);
    }
    return true;
}

bool areCompatible(FunctionType* caller,FunctionType* callee) {

    bool are_comp = false;

    if (caller->isVarArg()) {

        are_comp = caller->getReturnType() == callee->getReturnType();

        int p;
        for (p = 0; p < caller->getNumParams(); p++)
            are_comp &= caller->getParamType(p) == callee->getParamType(p);

    }
    else {
        are_comp = caller == callee;
    }

    return are_comp;
}

ValueMetadata ValueMetadata::extractReturnMetadata(
    const SVFG* vfg, const Value* val) {

    SVFIR* pag = SVFIR::getPAG();

    PointerAnalysis* pta = vfg->getPTA(); 

    PAGNode* pNode = pag->getGNode(pag->getValueNode(val));
    // const VFGNode* vNode = vfg->getDefSVFGNode(pNode);
    // need a stack -> FILO
    // let S be a stack
    // std::vector<Path> worklist;
    // std::set<Path> visited;
    // S.push(v)
    // worklist.push_back(Path(vNode));

    ValueMetadata mdata;
    mdata.setValue(val);

    SVFModule *svfModule = pag->getModule();

    ICFG* icfg = pag->getICFG();

    const Function *fun = pNode->getFunction();
    const SVFFunction *svfun = svfModule->getSVFFunction(fun);

    FunExitICFGNode *fun_exit = icfg->getFunExitICFGNode(svfun);

    Type *retType = fun->getReturnType();

    PHIFun phi;
    PHIFunInv phi_inv;
    getPhiFunction(svfModule, icfg, &phi, &phi_inv);  

    // std::set<const VFGNode*> alloca_set;
    // std::set<const Value*> allocainst_set;
    std::set<const Instruction*> allocainst_set;
    // std::set<const Value*> bitcastinst_set;

    // how many alloca?
    FunEntryICFGNode *entry_node = icfg->getFunEntryICFGNode(svfun);

    std::stack<std::pair<ICFGNode*,std::stack<ICFGEdge*>>> working;

    std::set<ICFGNode*> visited;

    std::stack<ICFGEdge*> empty_stack;
    working.push(std::make_pair(entry_node, empty_stack));

    AccessTypeSet *ats = mdata.getAccessTypeSet();

    while(!working.empty()) {

        auto el = working.top();
        working.pop();

        ICFGNode *node = el.first;
        std::stack<ICFGEdge*> curr_stack = el.second;

        if (auto intra_stmt = SVFUtil::dyn_cast<IntraICFGNode>(node)) {
            if (auto alloca = SVFUtil::dyn_cast<AllocaInst>(
                intra_stmt->getInst())) {
                // outs() << "[INFO] alloca " << *alloca << "\n";
                if (alloca->getAllocatedType() == retType) {
                    // outs() << "[INFO] => type ok!\n";
                    // alloca_set.insert(vfgnode);
                    allocainst_set.insert(alloca);
                }
            } else if (auto callinst = SVFUtil::dyn_cast<CallInst>(
                intra_stmt->getInst())) {
                // outs() << "[INFO] callinst " << *callinst << "\n";
                FunctionType *ftype = callinst->getFunctionType();
                if (ftype->getReturnType() == retType) {
                    // outs() << "[INFO] => type ok!\n";
                    // alloca_set.insert(vfgnode);
                    allocainst_set.insert(callinst);
                }
            } else if (auto bitcastinst = SVFUtil::dyn_cast<BitCastInst>(
                intra_stmt->getInst())) {
                if (bitcastinst->getDestTy() == retType) {
                    // outs() << "[INFO] bitcastinst " << *bitcastinst << "\n";
                    // outs() << "[INFO] => type ok!\n";
                    // alloca_set.insert(vfgnode);
                    allocainst_set.insert(bitcastinst);
                    // bitcastinst_set.insert(bitcastinst);
                }
            }
        } else if (auto call_node = SVFUtil::dyn_cast<CallICFGNode>(node)) {
            // Handling calls
            if (!consider_indirect_calls && call_node->isIndirectCall())
                    continue;

            auto callee = SVFUtil::getCallee(call_node->getCallSite());
            auto inst = SVFUtil::dyn_cast<CallInst>(call_node->getCallSite());
            // outs() << "[INFO] callinst2 " << *inst << "\n";
            FunctionType *ftype = inst->getFunctionType();
            if (ftype->getReturnType() == retType) {
                // outs() << "[INFO] => type ok!\n";
                // alloca_set.insert(vfgnode);
                allocainst_set.insert(inst);
            }

            if (callee != nullptr) {
                std::string fun = callee->getName();
                // TODO: add an allow-list
                // malloc handler
                // bool _ignored = 
                //     predefinedAccessTypeDispatcher(&mdata, fun, nullptr);
                // OLD STUFF
                // AccessType acNode(retType);
                //     // no need to set field, empty field set is what I need
                //     acNode.setAccess(AccessType::Access::create);
                //     ats.insert(acNode, node);
            }
        }  

        // We'll go throught the children and add unknown ones to our work list.
        if (node->hasOutgoingEdge()) {
            ICFGNode::const_iterator it = node->OutEdgeBegin();
            ICFGNode::const_iterator eit = node->OutEdgeEnd();
        
            for (; it != eit; ++it) {
                ICFGEdge *edge = *it;
                ICFGNode *dst = edge->getDstNode();

                if (visited.find(dst) != visited.end()) {
                    // We've seen it already
                    continue;
                }
                
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
                    ICFGEdge *next_ret = phi[call_edge];
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
    // We have visited all the nodes

    // std::map<const Instruction*, AccessTypeSet> all_ats;
    std::map<const Value*, ValueMetadata> all_ats;
    for (auto a: allocainst_set) {
        // outs() << "[INFO] paraAT() " << *a << " -- ";
        // outs() << a->getFunction()->getName().str() << "\n";
        ValueMetadata l_ats = ValueMetadata::extractParameterMetadata(vfg, a, retType);

        // outs() << "[STARTING POINT] " << *a << "\n";
        // outs() << l_ats.toString(true) << "\n";
        // exit(1);

        bool do_not_return = true;
        for (auto at: *l_ats.getAccessTypeSet()) {
            if (at.getAccess() == AccessType::Access::ret) {
                auto l_ats_all_nodes = at.getICFGNodes();
                for (auto inst: l_ats_all_nodes) {
                    if (inst == fun_exit) {
                        for (auto at2: *l_ats.getAccessTypeSet())
                            for (auto inst2:  at.getICFGNodes())
                                ats->insert(at2, inst2);
                        do_not_return = false;
                        break;
                    }
                }
            }
        }   
        if (do_not_return)
            all_ats[a] = l_ats;
    }

    // outs() << "LET'S SEE WHAT FUNCTIONS WE HAVE HERE!!!\n";
    // exit(1);

    // MERGE traces that lead to a return value (and ignoring the others)
    bool ast_is_changed = true;
    while (ast_is_changed) {

        ast_is_changed = false;

        auto ats_all_nodes_before = ats->getAllICFGNodes();

        for (auto atsx: all_ats) {
            auto ats_all_nodes = ats_all_nodes_before;
            auto atsx_all_nodes = atsx.second
                                        .getAccessTypeSet()
                                        ->getAllICFGNodes();
            for (auto inst: atsx_all_nodes) {
                if (ats_all_nodes.find(inst) != ats_all_nodes.end()) {
                    // I found something in common
                    if (ValueMetadata::debug) {
                        outs() << "[MATCHING]" << inst->toString()  << "\n";
                    }
                    for (auto atx:  *atsx.second.getAccessTypeSet())
                        for (auto inst: atx.getICFGNodes())
                            ats->insert(atx, inst);
                    break;
                }
            }
        }

        auto ats_all_nodes_merged = ats->getAllICFGNodes();

        ast_is_changed = ats_all_nodes_merged != ats_all_nodes_before;

    }

    return mdata;

}

std::string ValueMetadata::extractDependentParameter(
    ValueMetadata* mdata, SVF::SVFG* svfg, const SVFFunction* fun) {

    std::string dependent_param = "";

    SVFIR* pag = SVFIR::getPAG();

    // DominatorTree dom_tree(*fun->getLLVMFun());
    // LoopInfo loop_info(dom_tree);

    PAG::FunToArgsListMap funmap_par = pag->getFunArgsMap();
    PAG::SVFVarList fun_params = funmap_par[fun];    

    // use this to find loops faster
    //  Loop* loop_info->getLoopFor(const BasicBlock *BB) const

    for (auto i: mdata->getIndexes()) {
        // outs() << "I: " << *i << "\n";

        llvm:: Instruction *ii = SVFUtil::dyn_cast<llvm::Instruction>(i);

        // just in case
        if (ii == nullptr)
            continue;

        DominatorTree dom_tree(*ii->getFunction());
        LoopInfo loop_info(dom_tree);
        Loop* l = loop_info.getLoopFor(ii->getParent());

        if (l == nullptr) {
            continue;
        }

        SmallVector<llvm::BasicBlock*> exits;
	    l->getExitingBlocks(exits);
        for (auto e: exits) {
            auto v = &e->back();
            // outs() << "V: " << *v << "\n";

            PAGNode* pV = pag->getGNode(pag->getValueNode(v));
            const VFGNode* vV = svfg->getDefSVFGNode(pV);
            PAGNode* pI = nullptr;
            PAGNode* pP = nullptr;

            bool index_control_loop = false;
            bool param_control_loop = false;
            for (auto i: mdata->getIndexes()) {
                pI = pag->getGNode(pag->getValueNode(i));
                const VFGNode* vI = svfg->getDefSVFGNode(pI);

                if (areConnected(vI,vV)) {
                    // outs() << "Index control Loop\n";
                    index_control_loop = true;
                    break;
                }
            }

            int p_idx = 0;
            for (auto p: fun_params) {
                // pP = const_cast<llvm::Value*>(p->getValue());
                pP = pag->getGNode(pag->getValueNode(p->getValue()));
                const VFGNode* vP = svfg->getDefSVFGNode(pP);
                // const_cast<llvm::Value*>(p->getValue());
                // outs() << "P: " << pP->toString() << "\n";
                if (areConnected(vP,vV)) {
                    // outs() << "Param control Loop\n";
                    param_control_loop = true;
                    break;
                } 
                p_idx++;
                // else
                //     outs() << "no control!\n";
            }

            if (param_control_loop && index_control_loop) {
                // outs() << "Index: " << pI->toString() << "\n";
                // outs() << "Param: " << pP->toString() << "\n";
                dependent_param = "param_" + std::to_string(p_idx);
            }
        }

    }

    return dependent_param;
}

// std::set<const VFGNode*> ValueMetadata::getDefinitionSet(const VFGNode *n) {
std::set<const VFGNode*> getDefinitionSet(const VFGNode *n) {

    std::set<const VFGNode*> definitions;

    std::set<const VFGNode*> visited;
    std::vector<const VFGNode*> worklist;

    worklist.push_back(n);
    while(!worklist.empty()) {
        auto n = worklist.back();
        worklist.pop_back();
        if (visited.find(n) != visited.end())
            continue;
        int n_parents = 0;
        for(auto in: n->getInEdges()) {
            auto pn = in->getSrcNode();
            worklist.push_back(pn);
            n_parents++;
            
        }
        // Maybe select some classes, e.g., alloca, param
        if (n_parents == 0) 
            definitions.insert(n);
        visited.insert(n);
    }

    return definitions;
}

// bool ValueMetadata::areConnected(const VFGNode *a, const VFGNode *b) {
bool areConnected(const VFGNode *a, const VFGNode *b) {

    std::set<const VFGNode*> defA = getDefinitionSet(a);
    std::set<const VFGNode*> defB = getDefinitionSet(b);
    std::set<const VFGNode*> intersection;

    // outs() << "DefA:" << a->toString() << "\n";
    // for (auto e: defA)
    //     outs() << e->toString() << "\n";
    // outs() << "DefB:" << b->toString() << "\n";
    // for (auto e: defB)
    //     outs() << e->toString() << "\n";

    std::set_intersection(
        defA.begin(), defA.end(),
        defB.begin(), defB.end(), 
        std::inserter(intersection, intersection.begin()));

    return !intersection.empty();

}


ValueMetadata ValueMetadata::extractParameterMetadata(
    const SVFG* vfg, const Value* val, Type *seek_type)
{
    SVFIR* pag = SVFIR::getPAG();

    PointerAnalysis* pta = vfg->getPTA(); 

    // some types I might need later
    LLVMContext &cxt = LLVMModuleSet::getLLVMModuleSet()->getContext();
    auto i8ptr_typ = PointerType::getInt8PtrTy(cxt);

    PAGNode* pNode = pag->getGNode(pag->getValueNode(val));
    const VFGNode* vNode = vfg->getDefSVFGNode(pNode);

    ValueMetadata mdata;
    mdata.setValue(val);

    // need a stack -> FILO
    // let S be a stack
    std::vector<Path> worklist;
    std::set<Path> visited;
    // S.push(v)
    // worklist.push_back(Path(vNode));
    worklist.push_back(Path(vNode, val, seek_type));

    // if (seek_type)
    //     outs() << "DEBUG: seek_type: " << *seek_type << "\n";

    // outs() << "DEBUG: val: " << *val << "\n";

    AccessTypeSet *ats = mdata.getAccessTypeSet();
    bool is_array;

    // std::set<std::string> visitedFunctions;

    bool continue_debug = false;

    /// Traverse along VFG
    // while S is not empty do
    while (!worklist.empty())
    {
        // v = S.pop()
        Path p = worklist.back();
        worklist.pop_back();

        const VFGNode* vNode = p.getNode();
        AccessType acNode = p.getAccessType();

        // visitedFunctions.insert(vNode->getFun()->getName());

        if (ValueMetadata::debug) {

            outs() << "\nWorking node:\n";
            outs() << "A.->" << vNode->toString() << "\n";
            outs() << "B.->" << vNode->getFun()->getName() << "\n";
            // outs() << "Stack size: " << p.getStackSize() << "\n";
            outs() << "AT: " << acNode.toString() << "\n";

            if (acNode.toString().rfind(ValueMetadata::debug_condition, 0) 
                == 0) {
                outs() << "[STOP]\n";
                for (auto h: p.getSteps()) {
                    outs() << h.first->toString() << "\n";
                    outs() << h.first->getFun()->getName() << "\n";
                    outs() << h.second.toString() << "\n";
                    outs() << "\n";
                }

                outs() << "-> last node <-\n";
                outs() << vNode->toString() << "\n";
                outs() << vNode->getFun()->getName() << "\n";
                outs() << acNode.toString() << "\n\n";

                outs() << "[IN EDGES]\n";
                for (VFGNode::const_iterator it = vNode->InEdgeBegin(), eit =
                            vNode->InEdgeEnd(); it != eit; ++it)
                {
                    VFGEdge* edge = *it;

                    if (SVFUtil::isa<SVF::DirectSVFGEdge>(edge))
                        outs() << "direct:\n";
                    else
                        outs() << "indirect:\n";

                    VFGNode* succNode = edge->getSrcNode();
                    outs() << succNode->toString() << "\n";
                }

                outs() << "[OUT EDGES]\n";
                for (VFGNode::const_iterator it = vNode->OutEdgeBegin(), eit =
                            vNode->OutEdgeEnd(); it != eit; ++it)
                {
                    VFGEdge* edge = *it;

                    if (SVFUtil::isa<SVF::DirectSVFGEdge>(edge))
                        outs() << "direct:\n";
                    else
                        outs() << "indirect:\n";

                    VFGNode* succNode = edge->getDstNode();
                    outs() << succNode->toString() << "\n";
                }
                
                exit(1);
            }
        }

        // if v is not labeled as discovered then
        if (visited.find(p) == visited.end()) {

            // outs() << "Process:\n";
            // outs() << vNode->toString() << "\n";

            // label v as discovered
            visited.insert(p);

            bool skipNode = false;

            // process the node!
            if (vNode->getNodeKind() == VFGNode::VFGNodeK::Load) {
                acNode.setAccess(AccessType::Access::read);
                ats->insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Store) {

                const Value* prevValue = p.getPrevValue();

                if (prevValue != nullptr &&
                    SVFUtil::isa<StoreInst>(vNode->getValue())) {
                        
                    auto inst = SVFUtil::dyn_cast<StoreInst>(vNode->getValue());

                    if (inst->getPointerOperand() == prevValue) {
                        acNode.setAccess(AccessType::Access::write);
                        ats->insert(acNode, vNode->getICFGNode());
                    } else if (inst->getValueOperand() == prevValue) {
                        acNode.setAccess(AccessType::Access::read);
                        ats->insert(acNode, vNode->getICFGNode());
                    }
                }

            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Gep &&
                      SVFUtil::isa<GetElementPtrInst>(vNode->getValue())) {
                
                // auto inst = (GetElementPtrInst *)vNode->getValue();
                auto inst = SVFUtil::dyn_cast<GetElementPtrInst>(vNode->getValue());

                // outs() << "[DEBUG] GEP under analysis:\n";
                // outs() << *inst << "\n";
                // outs() << vNode->toString() << "\n";

                auto sType = inst->getSourceElementType();
                auto dType = inst->getResultElementType();
                auto pType = inst->getPointerOperandType();

                // outs() << "[DEBUG]\n";

                // outs() << "sType:\n";
                // outs() << *sType << "\n";

                // outs() << "dType:\n";
                // outs() << *dType << "\n";

                // outs() << "pType:\n";
                // outs() << *pType << "\n";

                // outs() << "acNode.getType():\n";
                // outs() << *acNode.getType() << "\n";

                // outs() << "[DEBUG END]\n";

                // this avoids us to move into strange pointer-offset opreations
                // that look like field access
                // if (SVFUtil::isa<llvm::StructType>(sType) && 
                //  AccessTypeSet::isSameType(pType, acNode.getType()) ) {
                if (TypeMatcher::compare_types(pType, acNode.getType())) {
                    if (inst->hasAllConstantIndices()) {

                        for (int pos = 1; pos <= inst->getNumIndices(); pos++) {
                            
                            if (pos == 1) {
                                AccessType tmpAcNode = acNode;
                                tmpAcNode.addField(-1);
                                tmpAcNode.setAccess(AccessType::Access::read);
                                ats->insert(tmpAcNode, vNode->getICFGNode());
                            } else {
                                ConstantInt *CI=dyn_cast<ConstantInt>(
                                            inst->getOperand(pos));
                                uint64_t idx = CI->getZExtValue();
                                acNode.addField(idx);
                                acNode.setType(dType);
                            }

                        }
                    } else if (acNode.getNumFields() == 0) {

                        is_array = !SVFUtil::isa<ConstantInt>(
                            inst->getOperand(1));
                        if (is_array) {
                            auto d = inst->getOperand(1);
                            mdata.addIndex(d);
                        }

                    }
                }
                // else {
                //     outs() << "[DEBUG] GEP incoherent: \n";

                //     outs() << "instruction:\n";
                //     outs() << vNode->toString() << "\n";

                //     outs() << "sType:\n";
                //     outs() << *sType << "\n";

                //     outs() << "dType:\n";
                //     outs() << *dType << "\n";

                //     outs() << "pType:\n";
                //     outs() << *pType << "\n";

                //     outs() << "acNode.getType():\n";
                //     outs() << *acNode.getType() << "\n";
                //     outs() << "\n";
                //     exit(1);
                // }
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Copy &&
                    SVFUtil::isa<Instruction>(vNode->getValue())) {
                auto inst = SVFUtil::dyn_cast<Instruction>(vNode->getValue());

                acNode.setAccess(AccessType::Access::read);
                ats->insert(acNode, vNode->getICFGNode());

                // XXX: casting operations complitate things a lot. For the time
                // being I just leave it.

                if (auto bitcastinst = SVFUtil::dyn_cast<BitCastInst>(inst)) {
                    auto dst_typ = bitcastinst->getDestTy();
                    auto src_typ = bitcastinst->getSrcTy();

                    // if (acNode.getNumFields() != 0 &&                        
                    //     TypeMatcher::compare_types(src_typ, acNode.getType())) {
                    if (TypeMatcher::compare_types(src_typ, acNode.getType())) {
                        acNode.setType(dst_typ);
                        ats->insert(acNode, vNode->getICFGNode());
                    }
                    else {
                        skipNode = true;    
                    }

                    // if (dst_typ != seek_type && dst_typ != i8ptr_typ) {
                    //     skipNode = true;
                    // }
                }
                // if (Instruction::isCast(inst->getOpcode()))
                //     skipNode = true;
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Cmp) {
                acNode.setAccess(AccessType::Access::read);
                ats->insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::BinaryOp) {
                acNode.setAccess(AccessType::Access::read);
                ats->insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::FRet) {
                // outs() << "[INFO] I found a FormalRet\n";
                // outs() << vNode->toString() << "\n";
                acNode.setAccess(AccessType::Access::ret);
                ats->insert(acNode, vNode->getICFGNode());
            }

            if (skipNode) {
                // outs() << "I skip\n";
                // outs() << vNode->toString() << "\n";
                continue;
            }

            p.setAccessType(acNode);
            p.setPrevValue(vNode->getValue());

            if (vNode->hasOutgoingEdge()) {
                // outs() << "\nChildren:\n";
                // for all edges from v to w in G.adjacentEdges(v) do 
                for (VFGNode::const_iterator it = vNode->OutEdgeBegin(), eit =
                            vNode->OutEdgeEnd(); it != eit; ++it)
                {
                    VFGEdge* edge = *it;

                    VFGNode* succNode2 = edge->getDstNode();
                    // outs() << "INSPECT?: " << succNode2->toString() << "\n";

                    // follow indirect jumps if a store, probably add a flag
                    if (vNode->getNodeKind() != VFGNode::VFGNodeK::Store) {
                        // try to follow only Direct Edges
                        if (SVFUtil::isa<SVF::IndirectSVFGEdge>(edge)) {
                            // VFGNode* succNode2 = edge->getDstNode();
                            // outs() << "SKIP: " << succNode2->toString() << "\n";
                            continue;
                        }
                    }
                    // outs() << "I PROCEED WITH THIS\n";

                    VFGNode* succNode = edge->getDstNode();

                    Path p_succ = p;
                    p_succ.addStep(vNode->getICFGNode());

                    bool ok_continue = true;

                    const CallICFGNode* cs = nullptr;
                    bool isACall = false;

                    if (auto call_node =
                        SVFUtil::dyn_cast<ActualParmVFGNode>(succNode)) {
                        cs = call_node->getCallSite();
                        isACall = true;
                    } else if (auto call_node = 
                        SVFUtil::dyn_cast<ActualINSVFGNode>(succNode)) {
                        cs = call_node->getCallSite();
                        isACall = true;
                    } else if (auto ret_node = 
                        SVFUtil::dyn_cast<ActualRetVFGNode>(succNode)) {
                        cs = ret_node->getCallSite();
                        isACall = false;
                    } else if (auto ret_node = 
                        SVFUtil::dyn_cast<ActualOUTSVFGNode>(succNode)) {
                        cs = ret_node->getCallSite();
                        isACall = false;
                    }


                    if (cs && isACall) {
                        // outs() << "[INFO] ActualParmVFGNode:\n";
                        p_succ.pushFrame(cs);
                        if (p_succ.getStackSize() >= MAX_STACKSIZE) {
                            ok_continue = false;
                            outs() << "[INFO] Stack size too big!\n";
                        } else if (cs->isIndirectCall()) {
                            ok_continue = false; // TODO CHECK WITH FLAVIO is is a stop flag to no go into children?
                            // outs() << "[INFO] Indirect call, I stop!\n";
                        // it is a direct call, check for stubs
                        } else {
                            if (!cs->isIndirectCall()) {
                                std::string fun = SVFUtil::getCallee(cs->getCallSite())->getName();

                                // outs() << "[DEBUG] I found this function: " 
                                //        << fun << "\n";

                                ok_continue = predefinedAccessTypeDispatcher(
                                    &mdata, fun, vNode, acNode);

                                // OLD
                                // if (fun == "free") {
                                //     ok_continue = false;
                                //     acNode.setAccess(AccessType::Access::del);
                                //     ats.insert(acNode, vNode->getICFGNode());
                                // }

                            }
                        }
                    }

                    // aka is a ret
                    if (cs && !isACall) {
                        ok_continue = p_succ.isCorrect(cs);
                        if (ok_continue)
                            p_succ.popFrame();
                    }

                    if (ok_continue) {
                        p_succ.setNode(succNode);
                        worklist.push_back(p_succ);
                    }
                    
                }
            }
            // else {
            //     outs() << "I HAVE NOT OUT EDGES!\n";
            // }
        }
    } 

    // outs() << "I visited these functions:\n";
    // for (auto x: visitedFunctions) {
    //     outs() << x << "\n";
    // }

    mdata.setIsArray(is_array);

    return mdata;
}

void FunctionConditionsSet::storeIntoJsonFile(
        FunctionConditionsSet fun_cond_set, 
        std::string filename, bool verbose) {

    Json::Value jsonResult = fun_cond_set.toJson(verbose);

    std::ofstream jsonOutFile(filename);
    Json::StreamWriterBuilder jsonBuilder;
    if (!verbose)
        jsonBuilder.settings_["indentation"] = "";
        
    std::unique_ptr<Json::StreamWriter> writer(
        jsonBuilder.newStreamWriter());

    writer->write(jsonResult, &jsonOutFile);
    jsonOutFile.close();

}

void FunctionConditionsSet::storeIntoTextFile(
        FunctionConditionsSet fun_cond_set, 
        std::string filename, bool verbose) {

    std::ofstream txtOutFile(filename);
    txtOutFile << fun_cond_set.toString(verbose);
    txtOutFile.close();
    
}
