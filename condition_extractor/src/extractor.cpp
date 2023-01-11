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

#include "GenericDominatorTy.h"
#include "Dominators.h"
#include "PostDominators.h"
#include "AccessType.h"
#include "PhiFunction.h"

#include "json/json.h"
#include <fstream> 

#include "md5/md5.h"


using namespace llvm;
using namespace std;
using namespace SVF;


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

static llvm::cl::opt<bool> useDominator("dom",
        llvm::cl::desc("Use Post/Dominators"), llvm::cl::init(false));
static llvm::cl::opt<bool> printDominator("print_dom",
        llvm::cl::desc("Print Post/Dominators"), llvm::cl::init(false));

static llvm::cl::opt<std::string> cacheFolder("cache_folder",
        llvm::cl::desc("Folder for cache"), llvm::cl::init(""));

Verbosity verbose;

// at1 over_dom at2 iif
// for each i2 in at2 . exists i1 in at1 s.t. i1 dom i2
bool dominatesAccessType(GenericDominatorTy *dom, AccessType at1, AccessType at2) {

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

void pruneAccessTypes(Dominator* dom, PostDominator* pDom, AccessTypeSet *ats_set) {

    // the pair is meant to be <CREATE, DELETE>, not the other way around
    std::set<std::pair<AccessType, AccessType>> pairs_create_delete;
    for (auto at1: *ats_set) {
        if (at1.getAccess() != AccessType::Access::create &&
            at1.getAccess() != AccessType::Access::del)
            continue;

        for (auto at2: *ats_set) {
            if (at2.getAccess() != AccessType::Access::create &&
                at2.getAccess() != AccessType::Access::del)
            continue;

            if (at1 == at2)
                continue;

            if (at1.getFields() == at2.getFields())
                // be sure create comes first
                if (at1.getAccess() == AccessType::Access::create)
                    pairs_create_delete.insert(std::make_pair(at1, at2));

        }
    }

    for (auto px: pairs_create_delete)
        // (delete, X) PostDom (create, X) => None *remove both*
        if (dominatesAccessType(pDom, px.second, px.first)) {
            ats_set->remove(px.first);
            ats_set->remove(px.second);
        // (create, X) Dom (delete, X) => (create, X)
        } else if (dominatesAccessType(dom, px.first, px.second))
            ats_set->remove(px.second);

    // the pair is meant to be <WRITE, READ>, not the other way around
    std::set<std::pair<AccessType, AccessType>> pairs_write_read;
    for (auto at1: *ats_set) {
        if (at1.getAccess() != AccessType::Access::write &&
            at1.getAccess() != AccessType::Access::read)
            continue;

        for (auto at2: *ats_set) {
            if (at2.getAccess() != AccessType::Access::write &&
                at2.getAccess() != AccessType::Access::read)
            continue;

            if (at1 == at2)
                continue;

            if (at1.getFields() == at2.getFields())
                // be sure write comes first
                if (at1.getAccess() == AccessType::Access::write)
                    pairs_write_read.insert(std::make_pair(at1, at2));
        }
    }

    for (auto px: pairs_write_read)
        // (write, X) Dom (read, X) => (write, X) 
        if (dominatesAccessType(dom, px.first, px.second))
            ats_set->remove(px.second);

}

std::string computeHash(std::string file_path) {
    md5::MD5 md5stream;

    std::ifstream a_file;
    a_file.open(file_path);

    //get length of file
    a_file.seekg(0, std::ios::end);
    size_t length = a_file.tellg();
    a_file.seekg(0, std::ios::beg);

    char *buffer = (char*) malloc(length);

    //read file
    a_file.read(buffer, length);
    md5stream.add(buffer, length);

    free(buffer);
    buffer = NULL;
    
    a_file.close();
    return md5stream.getHash();
}

inline bool doesFileExists(const std::string& name) {
    // outs() << "does it exists?\n";
    // outs() << name << "\n";
    // exit(1);
    ifstream myfile;
    myfile.open(name);
    if(myfile) {
        myfile.close();
        return true;
    } else {
        return false;
    }
}

std::string getCacheDomFile(std::string fun_name) {
    return cacheFolder + "/" + computeHash(InputFilename) + "_" + fun_name + "_dom.txt";
}

std::string getCachePostDomFile(std::string fun_name) {
    return cacheFolder + "/" + computeHash(InputFilename) + "_" + fun_name + "_postdom.txt";
}

// bool thereIsCache(std::string fun_name) {
//     std::string cache_dom = getCacheDomFile(fun_name);
//     std::string cache_postdom = getCachePostDomFile(fun_name);
//     return exists_file(cache_dom) && exists_file(cache_postdom);
// }

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

    verbose = Verbose;
    if (verbose >= Verbosity::v2) {
        AccessTypeSet::debug = true;
        AccessTypeSet::debug_condition = DebugCondition;
    }

    std::vector<std::string> functions;

    if (all_functions) {
        outs() << "[INFO] I analyze all the functions\n";

        ifstream f(LibInterface);

        Json::Value root;   
        Json::Reader reader;

        std::string line;
        while (std::getline(f, line)) {
            // outs() << line << "\n";
            bool parsingSuccessful = reader.parse( line.c_str(), root );
            if ( !parsingSuccessful )
            {
                outs() << "Failed to parse "
                    << reader.getFormattedErrorMessages();
                exit(1);
            }
            functions.push_back(root["function_name"].asString());
        }

        f.close();
    }
    else {
        outs() << "[INFO] analyzing function: " << function << "\n";
        functions.push_back(function);
    }

    if (OutputType == OutType::stdo)
        outs() << "[WARNING] outputting in stdout, ignoring OutputFile\n";

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
    // Andersen* point_to_analysys = AndersenWaveDiff::createAndersenWaveDiff(pag);
    FlowSensitive* point_to_analysys = FlowSensitive::createFSWPA(pag);
    // AndersenSCD* point_to_analysys = AndersenSCD::createAndersenSCD(pag);
    // TypeAnalysis* point_to_analysys = new TypeAnalysis(pag);
    // point_to_analysys->analyze();

    Dominator *dom = nullptr;
    PostDominator *pDom = nullptr;

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

    FunctionConditionsSet fun_cond_set;

    outs() << "[INFO] running analysis...\n";
    for (auto f: functions) {

        FunctionConditions fun_conds;

        fun_conds.setFunctionName(f);

        for (auto const& x : funmap_par) {
            const SVFFunction *fun = x.first;
            if ( fun->getName() != f)
                continue;

            outs() << "[INFO] processing params for: " << 
                        fun->getName() << "\n";

            for (auto const& p : x.second) {
                if (verbose >= Verbosity::v1)
                    outs() << "[INFO] param: " << p->toString() << "\n";
                AccessTypeSet parameterAccessTypeSet = 
                    AccessTypeSet::extractParameterAccessType(
                    svfg, p->getValue());

                // auto param_key = "param_" + std::to_string(pn);
                // functionResult[param_key] = parameterAccessTypeSet.toJson();

                fun_conds.addParameterAccessTypeSet(parameterAccessTypeSet);

            }
        }

        for (auto const& x : funmap_ret) {
            const SVFFunction *fun = x.first;
            if ( fun->getName() != f)
                continue;

            auto p = x.second;
            if (verbose >= Verbosity::v1)
                outs() << "[INFO] return: " << p->toString();
            AccessTypeSet returnAccessTypeSet =
                AccessTypeSet::extractReturnAccessType(svfg, p->getValue());

            // functionResult["return"] = returnAccessTypeSet.toJson();
            // jsonResult.append(functionResult);
            fun_conds.setReturnAccessTypeSet(returnAccessTypeSet);
        }

        if (useDominator) {
            SVF::SVFModule::llvm_iterator it = svfModule->llvmFunBegin();
            SVF::SVFModule::llvm_iterator eit = svfModule->llvmFunEnd();
            for (;it != eit; ++it) {
                const SVFFunction *fun = svfModule->getSVFFunction(*it);
                if ( fun->getName() != f)
                    continue;

                std::string fun_name = fun->getName();

                outs()  << "[INFO] computing dominators for: " <<
                            fun_name << "\n";

                FunEntryICFGNode *fun_entry = icfg->getFunEntryICFGNode(fun);
                FunExitICFGNode *fun_exit = icfg->getFunExitICFGNode(fun);

                std::string dom_cache_file = getCacheDomFile(fun_name);
                std::string postdom_cache_file = getCachePostDomFile(fun_name);

                dom = new Dominator(point_to_analysys, fun_entry);
                if (cacheFolder != "" && doesFileExists(dom_cache_file)) {
                    outs() << "[INFO] There is DOM cache, loading it\n";
                    dom->loadDom(dom_cache_file);
                } else {
                    outs() << "[INFO] No DOM cache, computing from scratch and save\n";
                    dom->createDom();
                    dom->dumpDom(dom_cache_file);
                }

                pDom = new PostDominator(point_to_analysys, fun_entry, fun_exit);
                if (cacheFolder != "" && doesFileExists(postdom_cache_file)) {
                    pDom->loadDom(postdom_cache_file);
                } else {
                    pDom->createDom();
                    pDom->dumpDom(postdom_cache_file);
                }

                if (printDominator) {
                    outs() << "[INFO] dumping dominators...\n";
                    std::string str1, str2;
                    if (dom) {
                        dom->dumpTransRed(dom_cache_file);
                    }

                    if (pDom) {
                        pDom->dumpTransRed(postdom_cache_file);
                    }
                }

                int num_param = fun_conds.getParameterAccessNum();

                for (int p = 0; p < num_param; p++) {
                    AccessTypeSet ats = fun_conds.getParameterAccessTypeSet(p);
                    pruneAccessTypes(dom, pDom, &ats);
                    fun_conds.replacedParameterAccessTypeSet(p, ats);
                }

                AccessTypeSet ats = fun_conds.getReturnAccessTypeSet();
                pruneAccessTypes(dom, pDom, &ats);
                fun_conds.setReturnAccessTypeSet(ats);

                delete dom;
                dom = nullptr;
                delete pDom;
                pDom = nullptr;
            }
        }

        fun_cond_set.addFunctionConditions(fun_conds);

    }

    if (OutputType == OutType::txt) {
        FunctionConditionsSet::storeIntoTextFile(
            fun_cond_set, OutputFile, verbose >= Verbosity::v1);
    } else if (OutputType == OutType::json) {
        FunctionConditionsSet::storeIntoJsonFile(
            fun_cond_set, OutputFile, verbose >= Verbosity::v1);
    } else if (OutputType == OutType::stdo) {
        outs() << fun_cond_set.toString(verbose >= Verbosity::v1);
    }

    outs() << fun_cond_set.getSummary();

    // clean up memory
    if (dom)
        delete dom;

    if (pDom)
        delete pDom;

    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();

    // I am not sure I need this
    // LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".svf.bc");
    SVF::LLVMModuleSet::releaseLLVMModuleSet();

    llvm::llvm_shutdown();
    return 0;
}

