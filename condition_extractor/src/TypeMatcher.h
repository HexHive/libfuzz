#ifndef INCLUDE_DOM_TYPEMATCHER_H_
#define INCLUDE_DOM_TYPEMATCHER_H_

#include "SVF-FE/LLVMUtil.h"
#include "md5/md5.h"

#include<string>

using namespace SVF;
using namespace llvm;
using namespace std;

class TypeMatcher {
    public:
        typedef std::map<Type*, std::string> TypeStringMap;

        static TypeStringMap type_hash_map;
        static TypeStringMap type_id_map;

        static std::string compute_id(llvm::StructType*);
        static std::string compute_hash(llvm::Type* t, 
            std::set<std::string> ids_done = {});
        static bool compare_types(llvm::Type*,llvm::Type*);
        static std::string remove_trail_num(std::string);

        static void precompute_type_hash(llvm::Module*);
};

#endif