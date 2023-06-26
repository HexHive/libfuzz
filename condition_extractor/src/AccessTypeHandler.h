#ifndef INCLUDE_DOM_ACCESSTYPE_HANDLER_H_
#define INCLUDE_DOM_ACCESSTYPE_HANDLER_H_

#include <map>
#include <utility>
#include "AccessType.h"
#include <unordered_map>

/**
See explanation in AccessType.cpp function: predefined_access_type_dispatcher

You can define handlers for specific functions that will manually update the access type set.
*/

bool isAnArray(const CallBase *c) {
    // I assume c is at lteast a memcpy-like function
    
    Module *m = LLVMModuleSet::getLLVMModuleSet()->getMainLLVMModule();
    const DataLayout &data_layout = m->getDataLayout();

    // outs() << "isAnArray?\n";
    // outs() << *c << "\n";

    bool obj_size_found = false;
    bool cpy_size_found = false;
    uint64_t obj_size = 0;
    uint64_t cpy_size = 0;

    if (auto dest = SVFUtil::dyn_cast<BitCastInst>(c->getArgOperand(0))) {
        // outs() << "id bitcast\n";
        // outs() << *dest << "\n";
        auto dst_tye = dest->getSrcTy();
        if (auto pnt = SVFUtil::dyn_cast<PointerType>(dst_tye)) {
            auto base_tye = pnt->getElementType();
            // outs() << "base type\n";
            // outs() << *base_tye << "\n";

            // need size in bytes
            obj_size = data_layout.getTypeStoreSizeInBits(base_tye);
            obj_size /= 8;
            // outs() << obj_size << "\n";
            obj_size_found = true;
        }
    }

    if (auto cs =dyn_cast<ConstantInt>(c->getArgOperand(2))) {
        cpy_size = cs->getZExtValue();
        // outs() << *copy_size << "\n";
        cpy_size_found = true;
    }

    if (obj_size_found && cpy_size_found && obj_size == cpy_size)
        return false;
 
    return true;
}

void addWrteToAllFields(ValueMetadata *mdata, AccessType atNode, 
    const ICFGNode* icfgNode) {
    auto t = atNode.getType();
    if (auto pt = SVFUtil::dyn_cast<llvm::PointerType>(t)) {

        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::write);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);

        t = pt->getElementType();
    }

    if (auto st = SVFUtil::dyn_cast<llvm::StructType>(t)) {
        
        for (int f = 0; f < st->getNumElements(); f++) {
            auto ft = st->getElementType(f);
            AccessType atField = atNode;
            atField.setAccess(AccessType::Access::write);
            atField.addField(f);
            atField.setType(ft);
            mdata->getAccessTypeSet()->insert(atField, icfgNode);
        }
    }

}

// H_SCOPE is a masked with C_RETURN and C_PARAM  asdf
// C_RETURN -> the handler is invoked by extractReturnMetadata
// C_PARAM -> the handler is invoked by extractParameterMetadata
#define C_RETURN 1 // 01
#define C_PARAM 2  // 10
typedef unsigned short H_SCOPE;

typedef bool (*Handler)(ValueMetadata*, std::string, 
    const ICFGNode*, const CallICFGNode*, int, AccessType, H_SCOPE);
typedef std::map<std::string, Handler> AccessTypeHandlerMap;

bool malloc_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num,
    AccessType atNode, H_SCOPE scope) {

    if (param_num == -1 && scope & C_RETURN) {
        // no need to set field, empty field set is what I need
        atNode.setAccess(AccessType::Access::create);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        return true;
    }
    if (param_num == 0 && atNode.getNumFields() == 0 && scope & C_PARAM) {
        atNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        mdata->setMallocSize(true);
        return false;
    }

    return false;
}

bool free_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num,
    AccessType atNode, H_SCOPE scope) {

    if (param_num == 0 && atNode.getNumFields() == 0 && scope & C_PARAM) {
        atNode.setAccess(AccessType::Access::del);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
    }

    return false;
}

bool open_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode, H_SCOPE scope) {

    if ((param_num == 0 || param_num == 1) && atNode.getNumFields() == 0 &&
        scope & C_PARAM) {
        atNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        mdata->setIsFilePath(true);

        // outs() << "icfgNode: " << icfgNode->toString() << "\n";
        // outs() << "cs: " << cs->toString() << "\n";
        // exit(1);
    }

    return false;
}

bool memcpy_hander(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode, H_SCOPE scope) {

    LLVMModuleSet *llvmModuleSet = LLVMModuleSet::getLLVMModuleSet();

    if ((param_num == 0 || param_num == 1) && atNode.getNumFields() == 0 && 
        scope & C_PARAM) {

        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);

        auto llvm_val = llvmModuleSet->getLLVMValue(cs->getCallSite());
        auto c = SVFUtil::dyn_cast<CallBase>(llvm_val);
        mdata->setIsArray(isAnArray(c));
        if (param_num == 1) {
            auto i = SVFUtil::dyn_cast<CallBase>(llvm_val);
            Value *v = i->getArgOperand(2);
            mdata->addFunParam(v);
        }
    }

    return false;
}

bool strlen_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode, H_SCOPE scope) {

    // outs() << "strlen_handler\n";

    if (param_num == 0 && atNode.getNumFields() == 0 && scope & C_PARAM) {
        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);
        mdata->setIsArray(true);
        // outs() << "HOOK IT!\n";
    }

    // exit(1);

    return false;
}

bool strcpy_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode, H_SCOPE scope) {

    if ((param_num == 0 || param_num == 1) && atNode.getNumFields() == 0 &&
        scope & C_PARAM) {
        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);
        mdata->setIsArray(true);
    }

    return false;
}

bool memset_hander(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode, H_SCOPE scope) {

    LLVMModuleSet *llvmModuleSet = LLVMModuleSet::getLLVMModuleSet();

    if (param_num == 0 && atNode.getNumFields() == 0 && scope & C_PARAM) {
        
        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);
        mdata->setIsArray(true);
        
        auto llvm_val = llvmModuleSet->getLLVMValue(cs->getCallSite());
        auto i = SVFUtil::dyn_cast<CallBase>(llvm_val);
        Value *v = i->getArgOperand(2);
        mdata->addFunParam(v);

        addWrteToAllFields(mdata, atNode, icfgNode);
    }

    return false;
}

bool calloc_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num,
    AccessType atNode, H_SCOPE scope) {

    if (param_num == -1 && scope & C_RETURN) {
        // no need to set field, empty field set is what I need
        atNode.setAccess(AccessType::Access::create);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);

        addWrteToAllFields(mdata, atNode, icfgNode);

        return true;
    }
    if (param_num == 1 && atNode.getNumFields() == 0 && scope & C_PARAM) {
        atNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        mdata->setMallocSize(true);
        return false;
    }

    return false;
}

bool posix_memalign_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num,
    AccessType atNode, H_SCOPE scope) {

    if (param_num == 0 && scope & C_RETURN) {
        // no need to set field, empty field set is what I need
        atNode.setAccess(AccessType::Access::create);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);

        return true;
    }

    return false;
}

static AccessTypeHandlerMap accessTypeHandlers = {
    {"malloc", &malloc_handler},
    {"free", &free_handler},
    {"open", &open_handler},
    {"open64", &open_handler},
    {"fopen", &open_handler},
    {"fopen64", &open_handler},
    {"llvm.memcpy.*", &memcpy_hander}, 
    {"strcpy", &strcpy_handler}, 
    {"strdup", &strcpy_handler}, 
    {"strlen", &strlen_handler}, 
    {"llvm.memset.*", &memset_hander},
    {"calloc", &calloc_handler}, 
    {"posix_memalign", &posix_memalign_handler} 
};

#endif /* INCLUDE_DOM_ACCESSTYPE_HANDLER_H_ */
