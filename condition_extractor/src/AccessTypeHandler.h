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
    const ICFGNode*, int, AccessType);
typedef std::map<std::string, Handler> AccessTypeHandler_map;

bool malloc_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, int param_num, AccessType atNode) {

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
    const ICFGNode* icfgNode, int param_num, AccessType atNode) {

    if (param_num == 0 && atNode.getNumFields() == 0) {
        atNode.setAccess(AccessType::Access::del);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
    }

    return false;
}

bool open_handler(ValueMetadata *mdata, std::string fun_name, 
    const ICFGNode* icfgNode, int param_num, AccessType atNode) {

    if (param_num == 0 && atNode.getNumFields() == 0) {
        atNode.setAccess(AccessType::Access::read);
        mdata->getAccessTypeSet()->insert(atNode, icfgNode);
        mdata->setIsFilePath(true);
    }

    return false;
}

static AccessTypeHandler_map accessTypeHandlers = {
    {"malloc", &malloc_handler},
    {"free", &free_handler},
    {"open", &open_handler}
};

#endif /* INCLUDE_DOM_ACCESSTYPE_HANDLER_H_ */