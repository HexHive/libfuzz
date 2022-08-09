#include "AccessType.h"

#include "SVF-FE/LLVMUtil.h"

#define MAX_STACKSIZE 20

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

/*!
 * An example to query/collect all the uses of a definition of a value along value-flow graph (VFG)
 */
AccessTypeSet AccessTypeSet::extractAccessType(
    const SVFG* vfg, const Value* val)
{
    SVFIR* pag = SVFIR::getPAG();

    PointerAnalysis* pta = vfg->getPTA(); 

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

        // if (p.getAccessType().getNumFields() >= 5) {
        // if (p.getAccessType().equals("(.9.-1, read)")) {
        //     outs() << "\n";
        //     outs() << "[INFO] FOUND:\n";
        //     for (auto h: p.getSteps()) {
        //         outs() << h.first->toString() << "\n";
        //         outs() << h.first->getFun()->getName() << "\n";
        //         outs() << h.second.toString() << "\n";
        //         outs() << "\n";
        //     }
        //     exit(1);
        // }

        // outs() << "\nWorking node:\n";
        // outs() << "A.->" << vNode->toString() << "\n";
        // outs() << "B.->" << vNode->getFun()->getName() << "\n";
        // outs() << "Stack size: " << p.getStackSize() << "\n";
        // outs() << "AT: " << acNode.toString() << "\n";

        // if (visited.size() > 100) {
        //     exit(1);
        // }
            // break;

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
                else {
                    skipNode = true;
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
                if (Instruction::isCast(inst->getOpcode()))
                    skipNode = true;
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::Cmp) {
                acNode.setAccess(AccessType::Access::read);
                ats.insert(acNode, vNode->getICFGNode());
            } else if (vNode->getNodeKind() == VFGNode::VFGNodeK::BinaryOp) {
                acNode.setAccess(AccessType::Access::read);
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

                    // try to follow only Direct Edges
                    if (!SVFUtil::isa<SVF::DirectSVFGEdge>(edge))
                        continue;

                    VFGNode* succNode = edge->getDstNode();
                    
                    // outs() << "1.-> " << succNode->toString() << "\n";
                    // outs() << "2.-> " << succNode->getFun()->getName() << "\n";

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
                            outs() << "[INFO] Stack si ze too big!\n";
                        } else if (cs->isIndirectCall()) {
                            ok_continue = false;
                            // outs() << "[INFO] Indirect call, I stop!\n";
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
        }
    } 

    // outs() << "I visited these functions:\n";
    // for (auto x: visitedFunctions) {
    //     outs() << x << "\n";
    // }

    return ats;
}