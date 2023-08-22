#include "Util/Options.h"
#include "SVFIR/SVFModule.h"
#include "WPA/WPAStat.h"
#include "WPA/Andersen.h"
#include "MemoryModel/PointsTo.h"
#include "Util/SVFUtil.h"
#include "SVF-LLVM/LLVMUtil.h"

#include "GlobalStruct.h"
#include "TypeMatcher.h"

using namespace SVF;
using namespace SVFUtil;

std::unique_ptr<GlobalStruct> GlobalStruct::gspta;

/// GlobalStruct analysis
void GlobalStruct::analyze() {

    // I always keep a string variable
    std::string str;

    // let's do the base class analysis
    FlowSensitive::analyze();

    LLVMModuleSet* llvmModuleSet = LLVMModuleSet::getLLVMModuleSet();
    SVFModule* svfModule =  LLVMModuleSet::getLLVMModuleSet()->getSVFModule();
    Module *m = LLVMModuleSet::getLLVMModuleSet()->getMainLLVMModule();

    std::map<std::string, std::set<const llvm::Function*>> fncs;

    for (auto g: svfModule->getGlobalSet()) {
        if (SVFUtil::isa<SVFConstant>(g)) {
            // SVFUtil::outs() << g->toString() << "\n";
            auto llvm_val = llvmModuleSet->getLLVMValue(g);
            get_function_pointers(llvm_val, &fncs);
        }
    }

    SVFIR::CallSiteToFunPtrMap map = pag->getIndirectCallsites();

    std::set<const CallICFGNode*> unresolved_calls;
    unsigned int tot_indirect_calls = 0;
    for (auto el: map) {
        auto icfg_node = el.first;
        auto node_id = el.second;
        auto target_set = pag->getIndCallSites(node_id);
        auto x = this->getPts(node_id);
        if (x.empty())
            unresolved_calls.insert(icfg_node);
        tot_indirect_calls++;
    }

    // auto ptacg = getPTACallGraph();
    auto ptacg = ptaCallGraph;

    SVFGEdgeSetTy svfgEdges;
    CallEdgeMap newEdges;

    // Actually resolving call targets
    for (auto cnode: unresolved_calls) {
        auto cs = cnode->getCallSite();
        auto llvm_inst = llvmModuleSet->getLLVMValue(cs);
        if (llvm_inst == nullptr)
            continue;

        // CallBase superclass of CallInst and InvokeInst
        auto llvm_cs = SVFUtil::dyn_cast<CallBase>(llvm_inst);
        if (llvm_cs == nullptr)
            continue;

        // auto dst_id = llvmModuleSet->getSVFValue(cnode);

        // llvm::raw_string_ostream(str) << *llvm_cs;
        // SVFUtil::outs() << str << "\n";


        auto fun_type = llvm_cs->getFunctionType();
        auto fun_type_hash = TypeMatcher::compute_hash(fun_type);

        // auto fun_caller = cnode->getFun();
        auto fun_caller = cnode->getCaller();

        const CallICFGNode* callBlockNode = pag->getICFG()->getCallICFGNode(cnode->getCallSite());

        for (auto f: fncs[fun_type_hash]) {
            auto fun_callee = llvmModuleSet->getSVFFunction(f);

            newEdges[callBlockNode].insert(fun_callee);
            getIndCallMap()[callBlockNode].insert(fun_callee);
            ptacg->addIndirectCallGraphEdge(callBlockNode, fun_caller, fun_callee);
        }
    }

    connectCallerAndCallee(newEdges, svfgEdges);
    updateConnectedNodes(svfgEdges);

    // check indirect calls again
    map = pag->getIndirectCallsites();

    std::set<const CallICFGNode*> unresolved_calls_2;
    tot_indirect_calls = 0;
    for (auto el: map) {
        auto icfg_node = el.first;
        auto node_id = el.second;
        auto target_set = pag->getIndCallSites(node_id);
        auto x = this->getPts(node_id);
        if (x.empty())
            unresolved_calls_2.insert(icfg_node);
        tot_indirect_calls++;
    }

}

/// Initialize analysis
void GlobalStruct::initialize() {
    FlowSensitive::initialize();
}

/// Finalize analysis
void GlobalStruct::finalize() {
    FlowSensitive::finalize();
}

void GlobalStruct::get_function_pointers(
    const llvm::Value* in_value, 
    std::map<std::string, std::set<const llvm::Function*>> *fncs) {

    std::stack<const llvm::Value*> working;
    working.push(in_value);

    std::set<const llvm::Value*> visited;    

    std::string str;

    while (!working.empty()) {
        auto value = working.top();
        working.pop();

        if (visited.find(value) != visited.end())
            continue;

        if (auto gv = SVFUtil::dyn_cast<GlobalVariable>(value)) {
            if (gv->hasInitializer()) {
                auto init = gv->getInitializer();
                working.push(init);
            }
        } else if (auto ca = SVFUtil::dyn_cast<ConstantAggregate>(value)) {
            for (unsigned int i = 0; i < ca->getNumOperands(); ++i) {
                auto op = ca->getOperand(i);
                working.push(op);
            }
        } else if (auto f = SVFUtil::dyn_cast<Function>(value)) {
            auto fun_type = f->getFunctionType();
            auto k = TypeMatcher::compute_hash(fun_type);
            (*fncs)[k].insert(f);
        }

        visited.insert(value);
    }
}
