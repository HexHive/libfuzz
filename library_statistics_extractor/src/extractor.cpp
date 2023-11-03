//===- svf-ex.cpp -- A driver example of SVF-------------------------------------//
//
//                     SVF: Static Value-Flow Analysis
//
// Copyright (C) <2013->  <Yulei Sui>
//

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//
//===-----------------------------------------------------------------------===//

/*
 // A driver program of SVF including usages of SVF APIs
 //
 // Author: Yulei Sui,
 */

#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "WPA/AndersenPWC.h"
#include "WPA/TypeAnalysis.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/Options.h"
#include "Util/SVFUtil.h"
#include "SVF-LLVM/LLVMUtil.h"

#include "GenericDominatorTy.h"
#include "Dominators.h"
#include "PostDominators.h"
#include "AccessType.h"
#include "PhiFunction.h"
#include "IBBG.h"
#include "TypeMatcher.h"
#include "LibfuzzUtil.h"
#include "GlobalStruct.h"

// for random sampling
#include <random>
#include <algorithm>
#include <iterator>

#include "json/json.h"
#include <fstream> 
#include <string>

#include "md5/md5.h"


using namespace std;
using namespace SVF;
using namespace SVFUtil;
using namespace LLVMUtil;

using namespace libfuzz;


// std because stdout gives conflict
enum OutType {txt, json, stdo};

enum Verbosity {v0, v1, v2, v3};

static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));
static llvm::cl::opt<std::string> FunctionName("function",
        llvm::cl::desc("<function name>"));
static llvm::cl::opt<std::string> LibInterface("interface",
        llvm::cl::desc("<library interface>"));

static llvm::cl::opt<Verbosity> Verbose("v",
        llvm::cl::desc("<verbose>"), llvm::cl::init(v0),
        llvm::cl::values(
            clEnumVal(v0, "No verbose"),
            clEnumVal(v1, "Report ICFG nodes"),
            clEnumVal(v2, "Report Paths if <debug_condition> is met"),
            clEnumVal(v3, "To implement, no effect atm")
        ));

static llvm::cl::opt<std::string> DebugCondition("debug_condition",
        llvm::cl::desc("<debug_condition> in combination with v2"));

static llvm::cl::opt<std::string> OutputFile("output",
        llvm::cl::desc("<output file>"), llvm::cl::init("conditions.json"));
static llvm::cl::opt<OutType> OutputType("t", cl::desc("Output type:"), 
        llvm::cl::init(stdo),
        llvm::cl::values(
            clEnumVal(txt , "Text file <output>"),
            clEnumVal(json, "Json file <output>"),
            clEnumVal(stdo, "Standard output, no <output>")
        ));

static llvm::cl::opt<bool> doIndJump("do_indirect_jumps",
        llvm::cl::desc("Include indirect jumps in the analysis"), 
        llvm::cl::init(false));

Verbosity verbose;

DataLayout *DL = nullptr;

void setDataLayout(const Function* F) {
  if (DL == nullptr)
    DL = new DataLayout(F->getParent());
}

int countReachableBB() {
// SVFValue* val = LLVMModuleSet::getLLVMModuleSet()->getSVFValue(llvmval);
//     SVFIR* pag = SVFIR::getPAG();

//     PointerAnalysis* pta = vfg->getPTA(); 

//     PAGNode* pNode = pag->getGNode(pag->getValueNode(val));
//     // const VFGNode* vNode = vfg->getDefSVFGNode(pNode);
//     // need a stack -> FILO
//     // let S be a stack
//     // std::vector<Path> worklist;
//     // std::set<Path> visited;
//     // S.push(v)
//     // worklist.push_back(Path(vNode));

//     LLVMModuleSet *llvmModuleSet = LLVMModuleSet::getLLVMModuleSet();

//     ValueMetadata mdata;
//     mdata.setValue(llvmval);

//     SVFModule *svfModule = pag->getModule();

//     ICFG* icfg = pag->getICFG();

//     auto svf_function = pNode->getFunction();
//     const Function *fun = SVFUtil::dyn_cast<Function>(
//         llvmModuleSet->getLLVMValue(svf_function));
//     const SVFFunction *svfun = pNode->getFunction();

//     FunExitICFGNode *fun_exit = icfg->getFunExitICFGNode(svfun);

//     Type *retType = fun->getReturnType();

//     if (!SVFUtil::isa<llvm::PointerType>(retType))
//         return mdata;

//     PHIFun phi;
//     PHIFunInv phi_inv;
//     getPhiFunction(svfModule, icfg, &phi, &phi_inv);  

//     // std::set<const VFGNode*> alloca_set;
//     // std::set<const Value*> allocainst_set;
//     std::set<const Instruction*> allocainst_set;
//     // std::set<const Value*> bitcastinst_set;

//     std::set<const SVFFunction*> visited_functions;

//     // how many alloca?
//     FunEntryICFGNode *entry_node = icfg->getFunEntryICFGNode(svfun);

//     std::stack<std::pair<ICFGNode*,std::stack<ICFGEdge*>>> working;

//     std::set<ICFGNode*> visited;

//     std::stack<ICFGEdge*> empty_stack;
//     working.push(std::make_pair(entry_node, empty_stack));

//     AccessTypeSet *ats = mdata.getAccessTypeSet();

//     while(!working.empty()) {

//         auto el = working.top();
//         working.pop();

//         ICFGNode *node = el.first;
//         std::stack<ICFGEdge*> curr_stack = el.second;

//         if (auto intra_stmt = SVFUtil::dyn_cast<IntraICFGNode>(node)) {

//             auto svfinst = intra_stmt->getInst();
//             auto llvminst = llvmModuleSet->getLLVMValue(svfinst);

//             if (auto alloca = SVFUtil::dyn_cast<AllocaInst>(llvminst)) {
//                 // // outs() << "[INFO] alloca " << *alloca << "\n";
//                 if (alloca->getAllocatedType() == retType) {
//                     // outs() << "[INFO] => type ok!\n";
//                     // alloca_set.insert(vfgnode);
//                     allocainst_set.insert(alloca);
//                 }
//             } else if (auto callinst = SVFUtil::dyn_cast<CallInst>(llvminst)) {
//                 // outs() << "[INFO] callinst " << *callinst << "\n";
//                 FunctionType *ftype = callinst->getFunctionType();
//                 if (ftype->getReturnType() == retType) {
//                     // outs() << "[INFO] => type ok!\n";
//                     // alloca_set.insert(vfgnode);
//                     allocainst_set.insert(callinst);
//                 }
//             } else if (auto bitcastinst = SVFUtil::dyn_cast<BitCastInst>(llvminst)) {
//                 if (bitcastinst->getDestTy() == retType) {
//                     // outs() << "[INFO] bitcastinst " << *bitcastinst << "\n";
//                     // outs() << "[INFO] => type ok!\n";
//                     // alloca_set.insert(vfgnode);
//                     allocainst_set.insert(bitcastinst);
//                     // bitcastinst_set.insert(bitcastinst);
//                 }
//             }
//         }
//         else if (auto call_node = SVFUtil::dyn_cast<CallICFGNode>(node)) {
//             // Handling calls
//             if (!consider_indirect_calls && call_node->isIndirectCall())
//                     continue;

//             auto callee = SVFUtil::getCallee(call_node->getCallSite());

//             auto svfinst = call_node->getCallSite();
//             auto llvminst = llvmModuleSet->getLLVMValue(svfinst);

//             auto inst = SVFUtil::dyn_cast<CallBase>(llvminst);
//             // outs() << "[INFO] callinst2 " << *inst << "\n";
//             FunctionType *ftype = inst->getFunctionType();
//             if (ftype->getReturnType() == retType) {
//                 // outs() << "[INFO] => type ok!\n";
//                 // alloca_set.insert(vfgnode);
//                 allocainst_set.insert(inst);
//             }

//             // if (callee != nullptr) {
//             //     std::string fun = callee->getName();
//             //     // malloc handler
//             //     AccessType acNode(retType);
//             //     handlerDispatcher(&mdata, fun, node, call_node, -1, 
//             //                         acNode, C_RETURN);

//             //     for (unsigned p = 0; p < ftype->getNumParams(); p++) {
//             //         handlerDispatcher(&mdata, fun, node, call_node, p, 
//             //                             acNode, C_RETURN);
//             //     }

//             // }
//         }  

//         // We'll go throught the children and add unknown ones to our work list.
//         // outs() << "NODE: " << node->toString() << "\n";
//         if (node->hasOutgoingEdge()) {
//             ICFGNode::const_iterator it = node->OutEdgeBegin();
//             ICFGNode::const_iterator eit = node->OutEdgeEnd();
        
//             for (; it != eit; ++it) {
//                 ICFGEdge *edge = *it;
//                 ICFGNode *dst = edge->getDstNode();

//                 if (visited.find(dst) != visited.end()) {
//                     // We've seen it already

//                     // BUG: if CallCFGEdge and already visited, then skip the
//                     // call and go to the next return                
//                     if(auto call_edge = SVFUtil::dyn_cast<CallCFGEdge>(edge)) {
//                         ICFGEdge *next_ret = phi[call_edge];
//                         ICFGNode *dst_new = next_ret->getDstNode();
//                         // next_ret
//                         // curr_stack.push(next_ret);
//                         working.push(std::make_pair(dst_new, curr_stack));
//                     }

//                     // outs() << "\talready visited: ";
//                     // outs() << dst->toString() << "\n";
//                     continue;
//                 }
                
//                 if(auto ret_edge = SVFUtil::dyn_cast<RetCFGEdge>(edge)) {

//                     if (curr_stack.size() != 0) {
//                         ICFGEdge *ret = curr_stack.top();
//                         if (ret_edge == ret) {
//                             curr_stack.pop();
//                             working.push(std::make_pair(dst, curr_stack));
//                             visited.insert(dst);
//                         }
//                     }
//                 }
//                 else if(auto call_edge = SVFUtil::dyn_cast<CallCFGEdge>(edge)) {
//                     ICFGEdge *next_ret = phi[call_edge];
//                     curr_stack.push(next_ret);
//                     working.push(std::make_pair(dst, curr_stack));
//                     visited.insert(dst);
//                 }
//                  else {
//                     working.push(std::make_pair(dst, curr_stack));
//                     visited.insert(dst);
//                 }
//             }
//         }

//     }
//     // We have visited all the nodes
//     return visited.size();
    return 0;
}


int main(int argc, char ** argv)
{

    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    LLVMUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Extract constraints from functions\n");
    
    bool all_functions = true;
    std::string function;
    if (FunctionName != "") {
        all_functions = false;
        function = FunctionName;
    }

    verbose = Verbose;
    if (verbose >= Verbosity::v2) {
        ValueMetadata::debug = true;
        ValueMetadata::debug_condition = DebugCondition;
    }

    if (Options::WriteAnder() == "ir_annotator")
    {
        LLVMModuleSet::getLLVMModuleSet()->preProcessBCs(moduleNameVec);
    }

    SVFUtil::outs() << "[INFO] Loading library...\n";

    LLVMModuleSet* llvmModuleSet = LLVMModuleSet::getLLVMModuleSet();
    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

    SVFUtil::outs() << "[INFO] Done\n";

    ValueMetadata::consider_indirect_calls = doIndJump;

    // I extract all the function names from the LLVM module
    std::set<std::string> functions_llvm;
    for (const SVFFunction* svfFun : svfModule->getFunctionSet() ){
        auto llvm_val = llvmModuleSet->getLLVMValue(svfFun);
        const llvm::Function* F = SVFUtil::dyn_cast<Function>(llvm_val);
        StringRef function_name = F->getName();
        functions_llvm.insert(function_name.str());
    }

    // std::vector<std::string> functions;
    std::set<std::string> functions;
    // read all the functions from apis_clang.json
    if (all_functions) {
        SVFUtil::outs() << "[INFO] I analyze all the functions\n";

        ifstream f(LibInterface);

        Json::Value root;   
        Json::Reader reader;

        std::string line;
        while (std::getline(f, line)) {
            // SVFUtil::outs() << line << "\n";
            bool parsingSuccessful = reader.parse( line.c_str(), root );
            if ( !parsingSuccessful )
            {
                SVFUtil::outs() << "Failed to parse "
                    << reader.getFormattedErrorMessages();
                exit(1);
            }

            // some clang functions are the result of macro expansion
            // they are not present in the llvm module
            std::string function_name = root["function_name"].asString();
            if (functions_llvm.find(function_name) != functions_llvm.end())
                functions.insert(function_name);
        }

        f.close();
    }
    else {
        SVFUtil::outs() << "[INFO] analyzing function: " << function << "\n";
        // functions.push_back(function);
        functions.insert(function);
    }

    if (OutputType == OutType::stdo)
        SVFUtil::outs() << "[WARNING] outputting in stdout, ignoring OutputFile\n";

    /// Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    ICFG* icfg = pag->getICFG();
    /// Create Andersen's pointer analysis
    // Andersen* point_to_analysys = AndersenWaveDiff::createAndersenWaveDiff(pag);
    // FlowSensitive* point_to_analysys = FlowSensitive::createFSWPA(pag);
    // AndersenSCD* point_to_analysys = AndersenSCD::createAndersenSCD(pag);
    // TypeAnalysis* point_to_analysys = new TypeAnalysis(pag);
    GlobalStruct *point_to_analysys = GlobalStruct::createSGWPA(pag);

    point_to_analysys->analyze();

    SVFUtil::outs() << "[INFO] Analysis done!\n";

    PAG::FunToArgsListMap funmap_par = pag->getFunArgsMap();

    // for (auto x: funmap_par) {
    //     SVFUtil::outs() << x.first << "\n";
    //     SVFUtil::outs() << x.second.size() << "\n";
    // }
    // exit(1);

    PAG::FunToRetMap funmap_ret = pag->getFunRets();

    PTACallGraph* callgraph = point_to_analysys->getPTACallGraph();
    builder.updateCallGraph(callgraph);
    icfg = pag->getICFG();
    icfg->updateCallGraph(callgraph);


    // icfg->dump("icfg_extractor");

    /// Sparse value-flow graph (SVFG)
    SVFGBuilder svfBuilder;
    SVFG* svfg = svfBuilder.buildFullSVFG(point_to_analysys);
    svfg->updateCallGraph(point_to_analysys);

    // svfg->dump("from_extractor");

    // I want to find a minimized set of APIs to analyze
    if (minimizeApi != "") {

        std::set<std::string> minimize_functions;

        SVF::SVFModule::const_iterator it = svfModule->begin();
        SVF::SVFModule::const_iterator eit = svfModule->end();
        for (;it != eit; ++it) {
            const SVFFunction *fun = *it;
            std::string fun_name = fun->getName();
            if (functions.find(fun_name) != functions.end()) {
                auto cg_node = callgraph->getCallGraphNode(fun);

                bool no_direct_in_edge = true;

                auto it2 = cg_node->directInEdgeBegin();
                auto eit2 = cg_node->directInEdgeEnd();
                for (; it2 != eit2; it2++){
                    no_direct_in_edge = false;
                    break;
                }
                
                if (no_direct_in_edge)
                    minimize_functions.insert(fun_name);
            }
        }

        // SVFUtil::outs() << "[INFO] The minimize set of function\n";
        std::ofstream minimizeApiFile(minimizeApi);
        for (auto f: minimize_functions) {
            minimizeApiFile << f << "\n";
        }
        minimizeApiFile.close();
        // SVFUtil::outs() << "[INFO] All function\n";
        // for (auto f: functions)
        //     SVFUtil::outs() << f << "\n";
    
        // SVFUtil::outs() << "[INFO] Total: " << minimize_functions.size() << "\n";
        // SVFUtil::outs() << "[INFO] Original: " << functions.size() << "\n";

    }

    // SVFUtil::outs() << " === EXIT FOR DEBUG ===\n";
    // exit(1);

    FunctionConditionsSet fun_cond_set;

    unsigned int tot_function = functions.size();
    unsigned int num_function = 0;

    SVFUtil::outs() << "[INFO] running analysis...\n";
    for (auto f: functions) {

        num_function++;
        FunctionConditions fun_conds;
        std::string prog = std::to_string(num_function) + "/" + 
                            std::to_string(tot_function);

        const SVFFunction *fun = x.first;
        if ( fun->getName() != f)
            continue;
    }


    if (OutputType == OutType::txt) {
        FunctionConditionsSet::storeIntoTextFile(
            fun_cond_set, OutputFile, verbose >= Verbosity::v1);
    } else if (OutputType == OutType::json) {
        FunctionConditionsSet::storeIntoJsonFile(
            fun_cond_set, OutputFile, verbose >= Verbosity::v1);
    } else if (OutputType == OutType::stdo) {
        SVFUtil::outs() << fun_cond_set.toString(verbose >= Verbosity::v1);
    }

    SVFUtil::outs() << fun_cond_set.getSummary();

    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();

    // I am not sure I need this
    // LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".svf.bc");
    SVF::LLVMModuleSet::releaseLLVMModuleSet();

    llvm::llvm_shutdown();
    return 0;
}
