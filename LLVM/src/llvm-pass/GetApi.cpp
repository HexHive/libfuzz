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
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"

#include "llvm/Support/CommandLine.h"

using namespace llvm;

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
    GetApi() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
      // ++HelloCounter;
      errs() << "**My GetAPI: ";
      errs().write_escaped(F.getName()) << '\n';
      return false;
    }
  };
}

char GetApi::ID = 0;
static RegisterPass<GetApi> X("getapi", "Get APIs from a module");

FunctionPass *llvm::createGetApiPass() {
  return new GetApi();
}
