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
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/DataLayout.h"

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

  typedef struct {
    public:
      string name; // arg name or return
      string flag; // val, ref, ret
      uint64_t size;
      string type;
      void set_from_type(Type *arg_type) {
        if (arg_type->isPtrOrPtrVectorTy()) {
            this->flag = "ref";
          } else {
            this->flag = "val";
          }
        raw_string_ostream ostream(type);
        arg_type->print(ostream);
      };
      void set_from_argument(Argument* arg) {

        this->name = arg->getName().str();

        Type *a_type = arg->getType();

        if (arg->hasPointeeInMemoryValueAttr())
          this->flag = "ret";
        else {
          if (a_type->isPtrOrPtrVectorTy()) {
            this->flag = "ref";
          } else {
            this->flag = "val";
          }
        }
        
        raw_string_ostream ostream(this->type);
        a_type->print(ostream);

      }
      string to_json() {
        string str_ret;

        str_ret += "{";
        str_ret += "\"name\": \"" + this->name + "\", ";
        str_ret += "\"flag\": \"" + this->flag + "\", ";
        str_ret += "\"size\": "  + to_string(this->size) + ", ";
        str_ret += "\"type\": \"" + this->type + "\"";
        str_ret += "}";

        return str_ret;
      }
  } argument_record;

  typedef struct {
    string function_name;
    argument_record return_info;
    vector<argument_record> arguments_info;
    string to_json() {
      string str_ret;

      str_ret += "{";
      str_ret += "\"function_name\": \"" + this->function_name + "\", ";
      str_ret += "\"return_info\": " + this->return_info.to_json() + ", ";
      str_ret += "\"arguments_info\": [";
      
      int max_arg = this->arguments_info.size();
      int n_arg = 0;
      for (auto arg : this->arguments_info) {
        str_ret += arg.to_json();
        if (n_arg < max_arg - 1)
          str_ret += ", ";
        n_arg++;
      }

      str_ret += "]"; // close argument_info list

      str_ret += "}";

      return str_ret;
    }
  } function_record;

  // GetApi - The first implementation, without getAnalysisUsage.
  struct GetApi : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid

#define MAX_PATH_LEN 1000
    char output_path[MAX_PATH_LEN] = { 0 };
    DataLayout *DL = nullptr;

    GetApi(): FunctionPass(ID) {
      if(getenv("LIBFUZZ_LOG_PATH"))
        strcpy(this->output_path, getenv("LIBFUZZ_LOG_PATH"));
      else {
        errs() << "LIBFUZZ_LOG_PATH not found, set it!\n";
        exit(1);
      }
    }

    void setDataLayout(Function &F) {
      if (this->DL == nullptr)
        this->DL = new DataLayout(F.getParent());
    }


    bool runOnFunction(Function &F) override {

      this->setDataLayout(F);

      function_record my_fun;

      Type * retType = F.getReturnType();
      StringRef function_name = F.getName();

      errs() << "Doing: " << function_name << "\n";

      my_fun.function_name = function_name.str();
      my_fun.return_info.set_from_type(retType);
      my_fun.return_info.size = this->estimate_size(retType);
      my_fun.return_info.name = "return";

      for(auto &arg : F.args()) {
          argument_record an_argument;
          an_argument.set_from_argument(&arg);
          an_argument.size = this->estimate_size(arg.getType(), arg.hasByValAttr());
          my_fun.arguments_info.push_back(an_argument);
      }
      
      this->print_function_record(my_fun);

      return false;
    }

    uint64_t estimate_size(Type* a_type, bool has_byval = false) {
      
      Type *typ_pointed = a_type;

      if (has_byval && isa<PointerType>(a_type) ) {

        PointerType *a_ptrtype = dyn_cast<PointerType>(a_type);

        typ_pointed = a_ptrtype->getElementType();

      }

      return typ_pointed->isSized() ? this->DL->getTypeSizeInBits(typ_pointed) : 0;
    }
    
    void print_function_record(function_record a_fun) {
        std::ofstream log(this->output_path, std::ios_base::app | std::ios_base::out);
        log << a_fun.to_json() << "\n";
        log.close();
    }
  };
}

char GetApi::ID = 0;
static RegisterPass<GetApi> X("getapi", "Get APIs from a module");

FunctionPass *llvm::createGetApiPass() {
  return new GetApi();
}
