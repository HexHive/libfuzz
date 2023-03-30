#ifndef INCLUDE_DOM_ACCESSTYPE_HANDLER_H_
#define INCLUDE_DOM_ACCESSTYPE_HANDLER_H_

#include <map>
#include "AccessType.h"
#include <unordered_map>

/**
See explanation in AccessType.cpp function: predefined_access_type_dispatcher

You can define handlers for specific functions that will manually update the access type set.
*/

typedef bool (*Handler)(ValueMetadata*, std::string, 
    const ICFGNode*, const CallICFGNode*, int, AccessType);
typedef std::map<std::string, Handler> AccessTypeHandlerMap;

bool malloc_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num,
    AccessType atNode) {

    if (param_num == -1) {
        // no need to set field, empty field set is what I need
        atNode.setAccess(AccessType::Access::create);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        return true;
    }
    if (param_num == 0 && atNode.getNumFields() == 0) {
        atNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        mdata->setMallocSize(true);
        return false;
    }

    return false;
}

bool free_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num,
    AccessType atNode) {

    if (param_num == 0 && atNode.getNumFields() == 0) {
        atNode.setAccess(AccessType::Access::del);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
    }

    return false;
}

bool open_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode) {

    if ((param_num == 0 || param_num == 1) && atNode.getNumFields() == 0) {
        atNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        mdata->setIsFilePath(true);
    }

    return false;
}

bool memcpy_hander(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode) {

    if ((param_num == 0 || param_num == 1) && atNode.getNumFields() == 0) {

        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);
        mdata->setIsArray(true);
        if (param_num == 1) {
            auto i = SVFUtil::dyn_cast<CallBase>(cs->getCallSite());
            Value *v = i->getArgOperand(2);
            mdata->addFunParam(v);
        }
    }

    return false;
}

bool strlen_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, const CallICFGNode* cs, int param_num, 
    AccessType atNode) {

    // outs() << "strlen_handler\n";

    if (param_num == 0 && atNode.getNumFields() == 0) {
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
    AccessType atNode) {

    if ((param_num == 0 || param_num == 1) && atNode.getNumFields() == 0) {
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
    AccessType atNode) {

    if (param_num == 0 && atNode.getNumFields() == 0) {

        AccessType tmpAcNode = atNode;
        tmpAcNode.addField(-1);
        tmpAcNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(tmpAcNode, icfgNode);
        mdata->setIsArray(true);
        
        auto i = SVFUtil::dyn_cast<CallBase>(cs->getCallSite());
        Value *v = i->getArgOperand(2);
        mdata->addFunParam(v);
    }

    return false;
}

static AccessTypeHandlerMap accessTypeHandlers = {
    {"malloc", &malloc_handler},
    {"free", &free_handler},
    {"open", &open_handler},
    {"fopen", &open_handler},
    {"llvm.memcpy.*", &memcpy_hander},
    {"strcpy", &strcpy_handler},
    {"strlen", &strlen_handler},
    {"llvm.memset.*", &memset_hander}
};

#endif /* INCLUDE_DOM_ACCESSTYPE_HANDLER_H_ */