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
    const VFGNode*, AccessType);
typedef std::map<std::string, Handler> AccessTypeHandler_map;

bool malloc_handler(ValueMetadata *mdata, std::string, 
    const VFGNode* node, AccessType atNode) {

    outs() << "malloc_handler\n";
    // AccessType acNode;
    // // no need to set field, empty field set is what I need
    // acNode.setAccess(AccessType::Access::create);
    // ats.insert(acNode, node);
    return true;
}

bool free_handler(ValueMetadata *mdata, std::string, 
    const VFGNode* node, AccessType atNode) {
    
    // outs() << "free_handler\n";
    atNode.setAccess(AccessType::Access::del);
    mdata->getAccessTypeSet()->insert(atNode, node->getICFGNode());
    return false;
}

static AccessTypeHandler_map accessTypeHandlers = {
    {"malloc", &malloc_handler},
    {"free", &free_handler},
};

#endif /* INCLUDE_DOM_ACCESSTYPE_HANDLER_H_ */