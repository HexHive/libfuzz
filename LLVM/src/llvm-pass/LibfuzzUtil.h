//===- HexTypeUtil.h - helper functions and classes for HexType ----*- C++-*-===//
////
////                     The LLVM Compiler Infrastructure
////
//// This file is distributed under the University of Illinois Open Source
//// License. See LICENSE.TXT for details.
////
////===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_UTILS_HEXTYPE_H
#define LLVM_TRANSFORMS_UTILS_HEXTYPE_H

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include <algorithm>
#include <set>
#include <string>
#include <list>
#include <vector>

namespace libfuzz {

  // extern cl::opt<bool> ClCreateCastRelatedTypeList;


  typedef struct {
    public:
      std::string name; // arg name or return
      std::string flag; // val, ref, ret
      uint64_t size;
      std::string type;
      void set_from_type(llvm::Type *arg_type) {
        if (arg_type->isPtrOrPtrVectorTy()) {
            this->flag = "ref";
          } else {
            this->flag = "val";
          }
        llvm::raw_string_ostream ostream(type);
        arg_type->print(ostream);
      };
      void set_from_argument(llvm::Argument* arg) {

        this->name = arg->getName().str();

        llvm::Type *a_type = arg->getType();

        if (arg->hasPointeeInMemoryValueAttr())
          this->flag = "ret";
        else {
          if (a_type->isPtrOrPtrVectorTy()) {
            this->flag = "ref";
          } else {
            this->flag = "val";
          }
        }
        
        llvm::raw_string_ostream ostream(this->type);
        a_type->print(ostream);

      }
      std::string to_json() {
        std::string str_ret;

        str_ret += "{";
        str_ret += "\"name\": \"" + this->name + "\", ";
        str_ret += "\"flag\": \"" + this->flag + "\", ";
        str_ret += "\"size\": "  + std::to_string(this->size) + ", ";
        str_ret += "\"type\": \"" + this->type + "\"";
        str_ret += "}";

        return str_ret;
      }
  } argument_record;

  typedef struct {
    std::string function_name;
    argument_record return_info;
    std::vector<argument_record> arguments_info;
    std::string to_json() {
      std::string str_ret;

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
  
  // void dumpCoerceMap(std::string func_name, unsigned arg_pos, std::string arg_original, std::string arg_coerce);
  void dumpCoerceMap(llvm::Function *func, unsigned arg_pos, std::string arg_original_name, std::string arg_original_type, llvm::Argument *arg_coerce);
  void dumpApiInfo(function_record a_fun);

  uint64_t estimate_size(llvm::Type* a_type, bool has_byval, llvm::DataLayout *DL);
  
} // llvm namespace
#endif  // LLVM_TRANSFORMS_UTILS_HEXTYPE_H
