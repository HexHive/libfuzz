//===- HexTypeUtil.cpp - helper functions and classes for HexType ---------===//
////
////                     The LLVM Compiler Infrastructure
////
//// This file is distributed under the University of Illinois Open Source
//// License. See LICENSE.TXT for details.
////
////===--------------------------------------------------------------------===//

#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/LibfuzzUtil.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include <sys/types.h>
#include <unistd.h>
#include <inttypes.h>
#include <filesystem>
#include <string>
#include <iostream>
#include <fstream>
#include <ios>

#define MAXLEN 1000

using namespace llvm;

namespace libfuzz {
  // cl::opt<bool> ClCreateCastRelatedTypeList(
  // "create-cast-related-type-list",
  // cl::desc("create casting related object list"),
  // cl::Hidden, llvm::cl::init(false));

  std::string CoerceFilePath = "";
  std::string ApiFilePath = "";

  std::string getCoerceFileLog() {
    if (CoerceFilePath == "") {
      if(getenv("LIBFUZZ_LOG_PATH")) {
        char buff[1000];
        strcpy(buff, getenv("LIBFUZZ_LOG_PATH"));
        CoerceFilePath = std::string(buff) + "/coerce.log";
      } else {
        errs() << "LIBFUZZ_LOG_PATH not found, set it!\n";
        exit(1);
      }
    }
    return CoerceFilePath;
  }

  std::string getApiFileLog() {
    if (ApiFilePath == "") {
      if(getenv("LIBFUZZ_LOG_PATH")) {
        char buff[1000];
        strcpy(buff, getenv("LIBFUZZ_LOG_PATH"));
        ApiFilePath = std::string(buff) + "/apis.log";
      } else {
        errs() << "LIBFUZZ_LOG_PATH not found, set it!\n";
        exit(1);
      }
    }
    return ApiFilePath;
  }

  void dumpLine(std::string line, std::string fileName) {
    std::ofstream log(fileName, std::ios_base::app | std::ios_base::out);
    log << line;
    log.close();
  }

  void dumpCoerceMap(std::string func_name, unsigned arg_pos, std::string arg_original, std::string arg_coerce) {
    std::string fileName = getCoerceFileLog();
    std::string line = func_name + "|" + std::to_string(arg_pos) + "|" + arg_original + "|" + arg_coerce + "\n";
    dumpLine(line, fileName);
  }

  void dumpApiInfo(function_record a_fun) {
    std::string fileName = getApiFileLog();
    std::string line = a_fun.to_json() + "\n";
    dumpLine(line, fileName);
  }

}
