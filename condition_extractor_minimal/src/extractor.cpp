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

#include "LibfuzzUtil.h"

// for random sampling
#include <random>
#include <algorithm>
#include <iterator>

#include <fstream> 


using namespace std;
using namespace SVF;
using namespace SVFUtil;
using namespace LLVMUtil;

using namespace libfuzz;


// // std because stdout gives conflict
// enum OutType {txt, json, stdo};

// enum Verbosity {v0, v1, v2, v3};

static llvm::cl::opt<std::string> InputFilename(cl::Positional,
        llvm::cl::desc("<input bitcode>"), llvm::cl::init("-"));
// static llvm::cl::opt<std::string> FunctionName("function",
//         llvm::cl::desc("<function name>"));
// static llvm::cl::opt<std::string> LibInterface("interface",
//         llvm::cl::desc("<library interface>"));

// static llvm::cl::opt<Verbosity> Verbose("v",
//         llvm::cl::desc("<verbose>"), llvm::cl::init(v0),
//         llvm::cl::values(
//             clEnumVal(v0, "No verbose"),
//             clEnumVal(v1, "Report ICFG nodes"),
//             clEnumVal(v2, "Report Paths if <debug_condition> is met"),
//             clEnumVal(v3, "To implement, no effect atm")
//         ));

// static llvm::cl::opt<std::string> DebugCondition("debug_condition",
//         llvm::cl::desc("<debug_condition> in combination with v2"));

// static llvm::cl::opt<std::string> ExtractDataLayout("data_layout",
//         llvm::cl::desc("<datalayout file>"), llvm::cl::init(""));

// static llvm::cl::opt<std::string> OutputFile("output",
//         llvm::cl::desc("<output file>"), llvm::cl::init("conditions.json"));
// static llvm::cl::opt<OutType> OutputType("t", cl::desc("Output type:"), 
//         llvm::cl::init(stdo),
//         llvm::cl::values(
//             clEnumVal(txt , "Text file <output>"),
//             clEnumVal(json, "Json file <output>"),
//             clEnumVal(stdo, "Standard output, no <output>")
//         ));

// static llvm::cl::opt<bool> useDominator("dom",
//         llvm::cl::desc("Use Post/Dominators"), llvm::cl::init(false));
// static llvm::cl::opt<bool> printDominator("print_dom",
//         llvm::cl::desc("Print Post/Dominators"), llvm::cl::init(false));

// static llvm::cl::opt<std::string> cacheFolder("cache_folder",
//         llvm::cl::desc("Folder for cache"), llvm::cl::init(""));

// static llvm::cl::opt<bool> doIndJump("do_indirect_jumps",
//         llvm::cl::desc("Include indirect jumps in the analysis"), 
//         llvm::cl::init(false));

// static llvm::cl::opt<std::string> minimizeApi("minimize_api",
//         llvm::cl::desc("Minimize API <out_folder>"), llvm::cl::init(""));

// Verbosity verbose;


DataLayout *DL = nullptr;

void setDataLayout(const Function* F) {
  if (DL == nullptr)
    DL = new DataLayout(F->getParent());
}


int main(int argc, char ** argv)
{

    int arg_num = 0;
    char **arg_value = new char*[argc];
    std::vector<std::string> moduleNameVec;
    LLVMUtil::processArguments(argc, argv, arg_num, arg_value, moduleNameVec);
    cl::ParseCommandLineOptions(arg_num, arg_value,
                                "Extract constraints from functions\n");
    
    
    if (Options::WriteAnder() == "ir_annotator")
    {
        LLVMModuleSet::getLLVMModuleSet()->preProcessBCs(moduleNameVec);
    }

    LLVMModuleSet* llvmModuleSet = LLVMModuleSet::getLLVMModuleSet();
    SVFModule* svfModule = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(moduleNameVec);

    // ValueMetadata::consider_indirect_calls = doIndJump;

    // I extract all the function names from the LLVM module
    std::set<std::string> functions_llvm;
    for (const SVFFunction* svfFun : svfModule->getFunctionSet() ){
        auto llvm_val = llvmModuleSet->getLLVMValue(svfFun);
        const llvm::Function* F = SVFUtil::dyn_cast<Function>(llvm_val);
        StringRef function_name = F->getName();
        functions_llvm.insert(function_name.str());
    }

    // Dump LLVM apis function per function
    for(const SVFFunction* svfFun : svfModule->getFunctionSet() ){
        auto llvm_val = llvmModuleSet->getLLVMValue(svfFun);
        const llvm::Function* F = SVFUtil::dyn_cast<Function>(llvm_val);

        setDataLayout(F);
        libfuzz::function_record my_fun;

        Type * retType = F->getReturnType();
        StringRef function_name = F->getName();
        bool is_vararg = F->isVarArg();
    
        SVFUtil::errs() << "Doing: " << function_name.str() << "\n";

        my_fun.function_name = function_name.str();
        my_fun.is_vararg = is_vararg ? "true" : "false";
        my_fun.return_info.set_from_type(retType);
        my_fun.return_info.size = libfuzz::estimate_size(retType, false, DL);
        my_fun.return_info.name = "return";

        for(const auto& arg : F->args()) {
            libfuzz::argument_record an_argument;
            an_argument.set_from_argument(arg);
            an_argument.size = libfuzz::estimate_size(arg.getType(), arg.hasByValAttr(), DL);
            my_fun.arguments_info.push_back(an_argument);
        }
      
      libfuzz::dumpApiInfo(my_fun);
    }
    /// Build Program Assignment Graph (SVFIR)
    SVFIRBuilder builder(svfModule);
    SVFIR* pag = builder.build();
    ICFG* icfg = pag->getICFG();
    /// Create Andersen's pointer analysis
    // Andersen* point_to_analysys = AndersenWaveDiff::createAndersenWaveDiff(pag);
    FlowSensitive* point_to_analysys = FlowSensitive::createFSWPA(pag);
    // AndersenSCD* point_to_analysys = AndersenSCD::createAndersenSCD(pag);
    // TypeAnalysis* point_to_analysys = new TypeAnalysis(pag);
    // point_to_analysys->analyze();


    // NOTE: this line should crashes
    PAG::FunToArgsListMap funmap_par = pag->getFunArgsMap();

    SVFUtil::outs() << "Does it work now?!\n";

    AndersenWaveDiff::releaseAndersenWaveDiff();
    SVFIR::releaseSVFIR();

    // I am not sure I need this
    // LLVMModuleSet::getLLVMModuleSet()->dumpModulesToFile(".svf.bc");
    SVF::LLVMModuleSet::releaseLLVMModuleSet();

    llvm::llvm_shutdown();
    return 0;
}
