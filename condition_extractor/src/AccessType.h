#ifndef INCLUDE_DOM_ACCESSTYPE_H_
#define INCLUDE_DOM_ACCESSTYPE_H_

#include <Graphs/ICFG.h>
#include <Graphs/SVFG.h>
#include <Graphs/GenericGraph.h>
#include "WPA/Andersen.h"

#include "PhiFunction.h"

using namespace SVF;
using namespace llvm;
using namespace std;

class AccessType {
    public:
        typedef enum _access { read, write, 
                               ret, none } Access;


    private:
        std::vector<int> fields;
        Access access;

    public:
        AccessType() {
            access = none;
        }
        ~AccessType() {fields.clear();}

        // copy assignment operator
        AccessType& operator=(const AccessType &rhs) {
            this->fields = rhs.fields;
            this->access = rhs.access;

            return *this;
        };

        void addField(int a_field) {
            fields.push_back(a_field);
        }

        std::vector<int> getFields() {
            return fields;
        }

        int getNumFields() {
            return fields.size();
        }

        void removeLastField() {
            if (getNumFields() == 0)
                return;
            fields.pop_back();
        }

        int getLastField() {
            if (getNumFields() == 0)
                return -1;
            return fields.back();
        }

        void setAccess(Access a_access) {
            access = a_access;
        }

        Access getAccess() {
            return access;
        }

        bool equals(std::string s) {return s == toString();}

        std::string toString() {

            std::string str;
            raw_string_ostream rawstr(str);

            // example of output:
            // (., write) -> write the whole pointer (all the fields)
            // (.1, read) -> read field in position 1
            // (.0.1, write) -> write subfield 1 of the field 0

            rawstr << "(.";
            int max_fields = getNumFields();
            int i = 0;
            for (int f: getFields()) {
                rawstr << f;
                if (i < max_fields - 1)
                    rawstr << ".";
                i++;
            }

            rawstr << ", ";
            if (access == Access::read) 
                rawstr << "read";
            else if (access == Access::write)
                rawstr << "write";
            else if (access == Access::ret)
                rawstr << "return";
            else if (access == Access::none)
                rawstr << "none";
            rawstr << ")";

            return rawstr.str();
        }

        bool operator<(const AccessType& rhs) const {
            if (fields == rhs.fields)
                return access < rhs.access;
            
            return fields < rhs.fields;
        }
};



class AccessTypeSet {
    // public:
    //      ICFGNodeSet;

    private:
        std::map<AccessType, std::set<const ICFGNode*>> ats;
        std::set<AccessType> ats_set;

    public:
        void insert(AccessType at, const ICFGNode* inst) {
            // outs() << "[DEBUG] insert: " << at.toString() << "\n";
            ats[at].insert(inst);
            ats_set.insert(at);
        }

        size_t size() const {
            return ats.size();
        }

        std::set<const ICFGNode*> getAllICFGNodes() const {
            std::set<const ICFGNode*> allNodes;

            for (auto p1: ats) {
                for (auto p2: p1.second) {
                    allNodes.insert(p2);
                }
            }

            return allNodes;
        }

        std::set<const ICFGNode*> getICFGNodes(AccessType at) const {
            auto insts = ats.find(at);
            if (insts == ats.end()) {
                std::set<const ICFGNode*> empty;
                return empty;
            }
            return insts->second;
        }

        void printICFGNodes(AccessType at) const {
            auto insts = ats.find(at);
            if (insts == ats.end())
                return;
            for (auto inst: insts->second)
                outs() << inst->toString() << "\n";
            outs() << "\n";
        }

        std::set<AccessType>::iterator begin() const {
            return ats_set.begin(); 
        }

        std::set<AccessType>::iterator end() const {
            return ats_set.end();
        }

        // std::string toString() const {
        //     return "aa";
        // }

        // bool operator<(const AccessTypeSet& rhs) const {
        //     // if (fields == rhs.fields)
        //     //     return access < rhs.access;
            
        //     // return fields < rhs.fields;
        //     return
        // }

        bool operator<(const AccessTypeSet& rhs) const {
            return ats < rhs.ats;
        }

    

    public: // static functions!
        static AccessTypeSet extractParameterAccessType(
            const SVFG*, const Value*, Type*);
        static AccessTypeSet extractReturnAccessType(
            const SVFG*, const Value*);

};

class Path {
    private:
        const VFGNode* node;
        AccessType access_type;
        const Value* prevValue;
        std::stack<const CallICFGNode*> stack;
        std::vector<std::pair<const ICFGNode*, AccessType>> history;

    public:
        Path(const VFGNode* p_node) {
            node = p_node;
            prevValue = nullptr;
        }

        void addStep(const ICFGNode* node) {
            history.push_back(std::make_pair(node, getAccessType()));
        }

        const std::vector<std::pair<const ICFGNode*, AccessType>> getSteps() {
            return history;
        }

        const Value* getPrevValue() {
            return prevValue;
        }

        void setPrevValue(const Value* a_prevValue) {
            prevValue = a_prevValue;
        }

        const VFGNode* getNode() {
            return node;
        }

        void setNode(const VFGNode* a_node) {
            node = a_node;
        }

        AccessType getAccessType() {return access_type;}

        void setAccessType(AccessType a_access_type) {
           access_type = a_access_type;
        }

        bool isCorrect(const CallICFGNode* edge) {
            if (getStackSize() == 0)
                return false;
            return stack.top() == edge;
        }

        const CallICFGNode* topFrame() {
            if (getStackSize() == 0)
                return nullptr;
            return stack.top();
        }

        void pushFrame(const CallICFGNode* cs) {
            stack.push(cs);
        }

        void popFrame() {
            stack.pop();
        }

        uint getStackSize() {return stack.size();}
        
        void dump() {
            // for (auto n: get_full_path()) {
            //     outs() << n->toString() << "\n";
            // }
            outs() << "<TBI>!!\n";
        }

        // for using it in std::set
        bool operator<(const Path& rhs) const 
        {
            if (node == rhs.node)
                return  access_type < rhs.access_type;
            else
                return node < rhs.node;
        }

        // copy assignment operator
        Path& operator=(const Path &rhs) {
            this->node = rhs.node;
            this->access_type = rhs.access_type;
            this->stack = rhs.stack;

            this->history = rhs.history;

            return *this;
        };

        std::string toString() {

            std::string str;
            raw_string_ostream rawstr(str);

            rawstr << "<" << access_type.toString() << ", ";
            rawstr << node->toString() << ">";

            return rawstr.str();
        }
};

#endif /* INCLUDE_DOM_ACCESSTYPE_H_ */