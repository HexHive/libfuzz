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

#include "SVF-FE/LLVMUtil.h"
#include "Graphs/SVFG.h"
#include "WPA/Andersen.h"
#include "WPA/AndersenPWC.h"
#include "WPA/TypeAnalysis.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/Options.h"

#include "Dominators.h"
#include "AccessType.h"
#include "PhiFunction.h"

#include "json/json.h"
#include <fstream> 


using namespace llvm;
using namespace std;
using namespace SVF;

static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));
static llvm::cl::opt<std::string> FunctionName("function",
        llvm::cl::desc("<function name>"));
static llvm::cl::opt<std::string> LibInterface("interface",
        llvm::cl::desc("<library interface>"));
static llvm::cl::opt<bool> Verbose("verbose",
        llvm::cl::desc("<verbose>"));
static llvm::cl::opt<bool> Verbose2("v",
        llvm::cl::desc("<verbose>"), cl::Hidden);


bool verbose;

// at1 over_dom at2 iif
// for each i2 in at2 . exists i1 in at1 s.t. i1 dom i2
bool dominatesAccessType(Dominator *dom, AccessType at1, AccessType at2) {

    uint n_instr_dominated = 0;
    bool is_dominated;
    for (auto i2: at2.getICFGNodes()) {
        is_dominated = false;
        for (auto i1: at1.getICFGNodes()) {
            is_dominated |= dom->dominates( const_cast<ICFGNode*>(i1),
                                            const_cast<ICFGNode*>(i2));
            if (is_dominated)
                break;
        }
        n_instr_dominated += is_dominated ? 1 : 0;
    }

    return n_instr_dominated == at2.getICFGNodes().size();

}

void pruneAccessTypes(Dominator* dom, AccessTypeSet ats_set) {

    std::set<std::pair<AccessType, AccessType>> pairs;

    for (auto at1: ats_set) {
        for (auto at2: ats_set) {
            if (at1.equals(at2.toString()))
                continue;

            if (at1.getFields() == at2.getFields()) {
                if (at1.getAccess() == AccessType::Access::write)
                    pairs.insert(std::make_pair(at1,at2));
                else if (at1.getAccess() == AccessType::Access::read)
                    pairs.insert(std::make_pair(at2,at1));
            }

        }
    }

    outs() << "I found these pairs:\n";
    for (auto px: pairs) {
        outs() << px.first.toString() << "\n";
        outs() << px.second.toString() << "\n";
        if (dominatesAccessType(dom, px.first, px.second))
            outs() << "write comes first!\n";
        if (dominatesAccessType(dom, px.second, px.first))
            outs() << "read comes first!\n";
        outs() << "=====\n";
    }

}

int main(int argc, char ** argv)
{

    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    LLVMUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Extract contraints from functions\n");
    
    bool all_functions = true;
    std::string function;
    if (FunctionName != "") {
        all_functions = false;
        function = FunctionName;
    }

    verbose = Verbose2 || Verbose;

    if (all_functions)
        outs() << "I analyze all the functions\n";
    else 
        outs() << "analyzing function: " << function << "\n";

    if (Options::WriteAnder == "ir_annotator")
    {
        LLVMModuleSet::getLLVMModuleSet()->preProcessBCs(moduleNameVec);
    }

    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);
    svfModule->buildSymbolTableInfo();

    /// Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder;
    SVFIR* pag = builder.build(svfModule);
    ICFG* icfg = pag->getICFG();

    /// Create Andersen's pointer analysis
    Andersen* point_to_analysys = AndersenWaveDiff::createAndersenWaveDiff(pag);
    // FlowSensitive* point_to_analysys = FlowSensitive::createFSWPA(pag);
    // AndersenSCD* point_to_analysys = AndersenSCD::createAndersenSCD(pag);
    // TypeAnalysis* point_to_analysys = new TypeAnalysis(pag);
    // point_to_analysys->analyze();

    Dominator *dom = nullptr;

    // // TEST FOR DOMINATORS!! DO NOT REMOVE
    // SVF::SVFModule::llvm_iterator it = svfModule->llvmFunBegin();
    // SVF::SVFModule::llvm_iterator eit = svfModule->llvmFunEnd();

    // outs() << "[INFO] running analysis...\n";
    // for (;it != eit; ++it) {
    //     const SVFFunction *fun = svfModule->getSVFFunction(*it);
        
    //     if ( !all_functions && fun->getName() != function)
    //         continue;

    //     outs() << fun->getName() << "\n";

    //     ICFGEdge* edge;
    //     ICFGNode* node;
    //     ICFGNode::const_iterator it2, eit2;

    //     std::set<const BasicBlock*> bbl_callsite, bbl_returnsite;

    //     FunEntryICFGNode *fun_entry = icfg->getFunEntryICFGNode(fun);

    //     dom = Dominator::createDom(point_to_analysys, fun_entry);
    //     // outs() << "[INFO] dumping dominators...\n";
    //     // std::string str;
    //     // raw_string_ostream rawstr(str);
    //     // rawstr <<  "dom_" << fun->getName();
    //     // // dom->dumpTransRed(rawstr.str());
    //     // dom->dumpDom(rawstr.str());

    //     // delete dom;
    // }
    // // TEST FOR DOMINATORS!! DO NOT REMOVE -- END
    

    // TEST FOR ACCESS TYPE!! DO NOT REMOVE
    PAG::FunToArgsListMap funmap_par = pag->getFunArgsMap();
    PAG::FunToRetMap funmap_ret = pag->getFunRets();

    PTACallGraph* callgraph = point_to_analysys->getPTACallGraph();
    builder.updateCallGraph(callgraph);
    icfg = pag->getICFG();
    icfg->updateCallGraph(callgraph);

    /// Sparse value-flow graph (SVFG)
    SVFGBuilder svfBuilder;
    SVFG* svfg = svfBuilder.buildFullSVFG(point_to_analysys);
    svfg->updateCallGraph(point_to_analysys);

    std::map<const PAGNode*, AccessTypeSet> param_access;
    
    Json::Value jsonResult(Json::arrayValue);


    outs() << "[INFO] running analysis...\n";
    for (auto const& x : funmap_par) {
        const SVFFunction *fun = x.first;
        if ( !all_functions && fun->getName() != function) {
            continue;
        }

        outs() << "[INFO] processing params for: " << fun->getName() << "\n";

        for (auto const& p : x.second) {
            outs() << "[INFO] param: " << p->toString() << "\n";
            param_access[p] = AccessTypeSet::extractParameterAccessType(svfg,p->getValue());
        }
    }

    for (auto const& x : funmap_ret) {
        const SVFFunction *fun = x.first;
        if ( !all_functions && fun->getName() != function) {
            continue;
        }

        // for (auto const& p : x.second) {
        //     param_access[p] = AccessTypeSet::extractParameterAccessType(svfg,p->getValue());
        // }

        auto p = x.second;
        AccessTypeSet returnAccessTypeSet = AccessTypeSet::extractReturnAccessType(svfg,p->getValue());
        // param_access[p] = returnAccessTypeSet;

        Json::Value functionResult;
        functionResult["functionName"] = fun->getName();
        functionResult["return"] = returnAccessTypeSet.toJson();
        jsonResult.append(functionResult);
    }

    

    // outs() << "[INFO] print results...\n";
    // for (auto const& p: param_access) {

    //     // pruneAccessTypes(dom, p.second);

    //     outs() << "For param:\n";
    //     outs() << p.first->toString() << "\n";
    //     outs() << "Collected " << p.second.size() << " access type:\n";
    //     for (auto at: p.second) {
    //         outs() << at.toString() << "\n";
    //         if (verbose)
    //             at.printICFGNodes();
    //     } 
    //     outs() << "\n";
    // }

    // TODO Zuka: handle output file somehow. maybe function name? or user input? ....
    std::ofstream jsonOutFile("json_output.json");
    Json::StreamWriterBuilder jsonBuilder;
    if (!verbose)
        jsonBuilder.settings_["indentation"] = "";
    std::unique_ptr<Json::StreamWriter> writer(jsonBuilder.newStreamWriter());
    writer->write(jsonResult, &jsonOutFile);
    jsonOutFile.close();

    // TEST FOR ACCESS TYPE!! DO NOT REMOVE -- END

    // example of access type domination
    // bool wDomR = dominatesAccessType(dom, atW_set, atR_set);
    // bool rDomW = dominatesAccessType(dom, atR_set, atW_set);

    // clean up memory
    if (dom)
        delete dom;

    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();

    LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".svf.bc");
    SVF::LLVMModuleSet::releaseLLVMModuleSet();

    llvm::llvm_shutdown();
    return 0;
}

