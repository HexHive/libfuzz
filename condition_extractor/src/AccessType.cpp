#include "AccessType.h"

#include "SVF-FE/LLVMUtil.h"

#define MAX_STACKSIZE 20

// static fields, mainly for debug
bool AccessTypeSet::debug = false;
std::string AccessTypeSet::debug_condition = "";

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

AccessTypeSet AccessTypeSet::extractRawPointerAccessType(
    const SVFG* vfg, const Value* val, Type* seek_type) {

    AccessTypeSet ats;

    // 0.A) only with BitCastInst
    assert(SVFUtil::isa<BitCastInst>(val) && "val must be a BitCastInt!");

    const BitCastInst* bitcast_inst = SVFUtil::dyn_cast<BitCastInst>(val);
    // 0.B) the BitCastInst must cast from my known type!
    assert(bitcast_inst->getDestTy() == seek_type && "val must cast from seek_type!");

    StructType* st = (StructType*)seek_type;

    SVFIR* pag = SVFIR::getPAG();


    LLVMModuleSet *llvmModuleSet = SVF::LLVMModuleSet::getLLVMModuleSet();
    PAGNode* pNode = pag->getGNode(pag->getValueNode(val));
    const VFGNode* vNode = vfg->getDefSVFGNode(pNode);

    const Type *seek_origin;
    if (SVFUtil::isa<PointerType>(seek_type)) {
        seek_origin = seek_type->getPointerElementType();
    } else {
        seek_origin = seek_type;
    }

    assert(SVFUtil::isa<StructType>(seek_origin) && 
            "I need a pointer to a struct!");
    
    const StructType *seek_struct = SVFUtil::dyn_cast<StructType>(seek_origin);

    const StructLayout *seek_layout;

    for (int i = 0; i < llvmModuleSet->getModuleNum(); i++) {
        Module *llvmModule = llvmModuleSet->getModule(i);
        DataLayout *datalayout = SVF::LLVMUtil::getDataLayout(llvmModule);
        if (datalayout->getStructLayout( 
                const_cast<StructType*>(seek_struct))) {
            seek_layout = datalayout->getStructLayout(
                const_cast<StructType*>(seek_struct));
            break;
        }
    }

    auto struct_offsets = nullptr; //seek_layout->getMemberOffsets();
    // this conversion is slow, but then I can use find() from the vector
    std::vector<uint64_t> struct_offsets_v; //= struct_offsets.vec();
    // outs() << "[DEBUG] field -> offset (bytes?)\n";
    // int i = 0;
    // for (auto o: struct_offsets) {
    //     outs() << " -> " << i << ": " << o << "\n";
    //     i++;
    // }
    // outs() << "\n";

    std::set<VFGNode*> generation_nodes;
    std::set<VFGNode*> gep_nodes;

    // 1) find the declartion: alloca or i8* return function
    for (VFGNode::const_iterator it = vNode->InEdgeBegin(), 
        eit = vNode->InEdgeEnd(); it != eit; ++it) {
        VFGEdge* edge = *it;

        // try to follow only Direct Edges
        if (SVFUtil::isa<SVF::DirectSVFGEdge>(edge)) {
            VFGNode* node = edge->getSrcNode();

            if (auto call = SVFUtil::dyn_cast<ActualRetVFGNode>(node)) {
                generation_nodes.insert(node);
            } else if (auto addr = SVFUtil::dyn_cast<AddrVFGNode>(node)) {
                generation_nodes.insert(node);
            }
        }
    }

    outs() << "[INFO] found these generators:\n";
    for (auto gn: generation_nodes) {
        outs() << " -> " << gn->toString() << "\n";
    }

    for (auto gn: generation_nodes) {
        for (VFGNode::const_iterator it = gn->OutEdgeBegin(), 
            eit = gn->OutEdgeEnd(); it != eit; ++it) {

            VFGEdge* edge = *it;

            if (!SVFUtil::isa<SVF::DirectSVFGEdge>(edge))
                continue;

            VFGNode* node = edge->getDstNode();

            if (auto gep = SVFUtil::dyn_cast<GetElementPtrInst>
                (node->getValue())) {
                gep_nodes.insert(node);
            }
        
        }
    }

    outs() << "[INFO] found these GEPs:\n";
    for (auto gep: gep_nodes) {
        auto inst = SVFUtil::dyn_cast<GetElementPtrInst>(gep->getValue());
        if (inst->hasAllConstantIndices() &&
            inst->getNumIndices() == 1) {
            outs() << " -> " << gep->toString() << "\n";

            ConstantInt *CI=dyn_cast<ConstantInt>(inst->getOperand(1));
            uint64_t idx = CI->getZExtValue();

            outs() << " -> offset: " << idx << "\n";

            auto idx_iterator = std::find(struct_offsets_v.begin(), 
                                            struct_offsets_v.end(), idx);
            if (idx_iterator != struct_offsets_v.end()) {
                unsigned int field = idx_iterator - struct_offsets_v.begin();
                outs() << " -> field: " << field << "\n";
            } else {
                outs() << " -> field not found :(\n";
            }

            outs() << "\n";
        }
    }

    exit(1);

    return ats;

}

AccessTypeSet AccessTypeSet::extractReturnAccessType(
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
    std::set<const Value*> allocainst_set;
    // std::set<const Value*> bitcastinst_set;

    // how many alloca?
    FunEntryICFGNode *entry_node = icfg->getFunEntryICFGNode(svfun);

    std::stack<std::pair<ICFGNode*,std::stack<ICFGEdge*>>> working;

    std::set<ICFGNode*> visited;

    std::stack<ICFGEdge*> empty_stack;
    working.push(std::make_pair(entry_node, empty_stack));

    AccessTypeSet ats;

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
            std::string fun = SVFUtil::getCallee(call_node->getCallSite())->getName();
            auto inst = SVFUtil::dyn_cast<CallInst>(call_node->getCallSite());
            // outs() << "[INFO] callinst2 " << *inst << "\n";
            FunctionType *ftype = inst->getFunctionType();
            if (ftype->getReturnType() == retType) {
                // outs() << "[INFO] => type ok!\n";
                // alloca_set.insert(vfgnode);
                allocainst_set.insert(inst);
            }

            // TODO: add an allow-list
            if (fun == "malloc") {
                AccessType acNode;
                // no need to set field, empty field set is what I need
                acNode.setAccess(AccessType::Access::create);
                ats.insert(acNode, node);
            }
        }  

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

    // std::map<const Instruction*, AccessTypeSet> all_ats;
    std::map<const Value*, AccessTypeSet> all_ats;
    for (auto a: allocainst_set) {
        // outs() << "[INFO] paraAT() " << *a << "\n";
        AccessTypeSet l_ats = AccessTypeSet::extractParameterAccessType(vfg, a, retType);

        // outs() << "[STARTING POINT] " << *a << "\n";
        // outs() << l_ats.toString(true) << "\n";
        // exit(1);

        bool do_not_return = true;
        for (auto at: l_ats)
            if (at.getAccess() == AccessType::Access::ret) {
                auto l_ats_all_nodes = at.getICFGNodes();
                for (auto inst: l_ats_all_nodes)
                    if (inst == fun_exit) {
                        for (auto at2: l_ats)
                            for (auto inst2:  at.getICFGNodes())
                                ats.insert(at2, inst2);
                        do_not_return = false;
                        break;
                    }
            }

        if (do_not_return)
            all_ats[a] = l_ats;
    }

    // MERGE traces that lead to a return value (and ignoring the others)
    bool ast_is_changed = true;
    while (ast_is_changed) {

        ast_is_changed = false;

        auto ats_all_nodes_before = ats.getAllICFGNodes();

        for (auto atsx: all_ats) {
            auto ats_all_nodes = ats_all_nodes_before;
            auto atsx_all_nodes = atsx.second.getAllICFGNodes();
            for (auto inst: atsx_all_nodes)
                if (ats_all_nodes.find(inst) != ats_all_nodes.end()) {
                    // I found something in common
                    if (AccessTypeSet::debug) {
                        outs() << "[MATCHING]" << inst->toString()  << "\n";
                    }
                    for (auto atx:  atsx.second)
                        for (auto inst: atx.getICFGNodes())
                            ats.insert(atx, inst);
                    break;
                }
        }

        auto ats_all_nodes_merged = ats.getAllICFGNodes();

        ast_is_changed = ats_all_nodes_merged != ats_all_nodes_before;

    }

    return ats;

}

AccessTypeSet AccessTypeSet::extractParameterAccessType(
    const SVFG* vfg, const Value* val, Type *seek_type)
{
    SVFIR* pag = SVFIR::getPAG();

    PointerAnalysis* pta = vfg->getPTA(); 

    // some types I might need later
    LLVMContext &cxt = LLVMModuleSet::getLLVMModuleSet()->getContext();
    auto i8ptr_typ = PointerType::getInt8PtrTy(cxt);

    PAGNode* pNode = pag->getGNode(pag->getValueNode(val));
    const VFGNode* vNode = vfg->getDefSVFGNode(pNode);
    // need a stack -> FILO
    // let S be a stack
    std::vector<Path> worklist;
    std::set<Path> visited;
    // S.push(v)
    worklist.push_back(Path(vNode));

    AccessTypeSet ats;

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

        if (AccessTypeSet::debug) {

            outs() << "\nWorking node:\n";
            outs() << "A.->" << vNode->toString() << "\n";
            outs() << "B.->" << vNode->getFun()->getName() << "\n";
            // outs() << "Stack size: " << p.getStackSize() << "\n";
            outs() << "AT: " << acNode.toString() << "\n";

            if (acNode.toString().rfind(AccessTypeSet::debug_condition, 0) 
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
                ats.insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Store) {

                const Value* prevValue = p.getPrevValue();

                if (prevValue != nullptr) {
                    auto inst = (StoreInst *)vNode->getValue();

                    if (inst->getPointerOperand() == prevValue) {
                        acNode.setAccess(AccessType::Access::write);
                        ats.insert(acNode, vNode->getICFGNode());
                    } else if (inst->getValueOperand() == prevValue) {
                        acNode.setAccess(AccessType::Access::read);
                        ats.insert(acNode, vNode->getICFGNode());
                    }
                }

            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Gep) {
                auto inst = (GetElementPtrInst *)vNode->getValue();
                auto sType = inst->getSourceElementType();

                // this avoids us to move into strange pointer-offset opreations
                // that look like field access
                if (SVFUtil::isa<llvm::StructType>(sType)) {
                    if (inst->hasAllConstantIndices()) {

                        for (int pos = 1; pos <= inst->getNumIndices(); pos++) {
                            
                            if (pos == 1) {
                                AccessType tmpAcNode = acNode;
                                tmpAcNode.addField(-1);
                                tmpAcNode.setAccess(AccessType::Access::read);
                                ats.insert(tmpAcNode, vNode->getICFGNode());
                            } else {
                                ConstantInt *CI=dyn_cast<ConstantInt>(
                                            inst->getOperand(pos));
                                uint64_t idx = CI->getZExtValue();
                                acNode.addField(idx);
                            }

                        }
                    }
                }
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Copy) {
                auto inst = (Instruction*)vNode->getValue();

                acNode.setAccess(AccessType::Access::read);
                ats.insert(acNode, vNode->getICFGNode());

                // XXX: casting operations complitate things a lot. For the time
                // being I just leave it.

                if (auto bitcastinst = SVFUtil::dyn_cast<BitCastInst>(inst)) {
                    auto dst_typ = bitcastinst->getDestTy();
                    if (dst_typ != seek_type && dst_typ != i8ptr_typ) {
                        skipNode = true;
                    }
                }
                // if (Instruction::isCast(inst->getOpcode()))
                //     skipNode = true;
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Cmp) {
                acNode.setAccess(AccessType::Access::read);
                ats.insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::BinaryOp) {
                acNode.setAccess(AccessType::Access::read);
                ats.insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::FRet) {
                // outs() << "[INFO] I found a FormalRet\n";
                // outs() << vNode->toString() << "\n";
                acNode.setAccess(AccessType::Access::ret);
                ats.insert(acNode, vNode->getICFGNode());
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
                    if (vNode->getNodeKind() != VFGNode::VFGNodeK::Store)
                        // try to follow only Direct Edges
                        if (SVFUtil::isa<SVF::IndirectSVFGEdge>(edge)) {
                            // VFGNode* succNode2 = edge->getDstNode();
                            // outs() << "SKIP: " << succNode2->toString() << "\n";
                            continue;
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
                            ok_continue = false;
                            // outs() << "[INFO] Indirect call, I stop!\n";
                        // it is a direct call, check for stubs
                        } else {
                            std::string fun = SVFUtil::getCallee(cs->getCallSite())->getName();

                            // outs() << "[DEBUG] I found this function: " 
                            //        << fun << "\n";

                            // TODO: add an allow-list
                            if (fun == "free") {
                                ok_continue = false;
                                acNode.setAccess(AccessType::Access::del);
                                ats.insert(acNode, vNode->getICFGNode());
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

    return ats;
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
