//===- GetApi.cpp - Extract API information from a target supposely go into a shared library
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Transforms/Utils/LibfuzzUtil.h"

#include <ios>
#include <fstream>
#include <vector>

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "getapi"

namespace llvm {
  cl::opt<bool> ClGetApi(
  "get-api-pass",
  cl::desc("Run GetAPI pass to extract API info"),
  cl::Hidden, llvm::cl::init(false));
}

// STATISTIC(HelloCounter, "Counts number of functions greeted");

namespace {

  // GetApi - The first implementation, without getAnalysisUsage.
  struct GetApi : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid

    #define MAX_PATH_LEN 1000
    char output_path[MAX_PATH_LEN] = { 0 };
    DataLayout *DL = nullptr;

    GetApi(): FunctionPass(ID) { }

    void setDataLayout(Function &F) {
      if (this->DL == nullptr)
        this->DL = new DataLayout(F.getParent());
    }


    bool runOnFunction(Function &F) override {

      this->setDataLayout(F);

      libfuzz::function_record my_fun;

      Type * retType = F.getReturnType();
      StringRef function_name = F.getName();

      errs() << "Doing: " << function_name << "\n";

      my_fun.function_name = function_name.str();
      my_fun.return_info.set_from_type(retType);
      my_fun.return_info.size = libfuzz::estimate_size(retType, false, this->DL);
      my_fun.return_info.name = "return";

      for(auto &arg : F.args()) {
          libfuzz::argument_record an_argument;
          an_argument.set_from_argument(&arg);
          an_argument.size = libfuzz::estimate_size(arg.getType(), arg.hasByValAttr(), this->DL);
          my_fun.arguments_info.push_back(an_argument);
      }
      
      libfuzz::dumpApiInfo(my_fun);

      return false;
    }
  };
}

char GetApi::ID = 0;
static RegisterPass<GetApi> X("getapi", "Get APIs from a module");

FunctionPass *llvm::createGetApiPass() {
  return new GetApi();
}
