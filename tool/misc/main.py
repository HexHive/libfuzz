#!/usr/bin/env python3.9

import argparse, tempfile, json, copy
from symbol import return_stmt
import sys, os, re
import clang.cindex


function_declarations = [] # List of AST node objects that are fucntion declarations
type_incomplete = set()    # List of incomplete types
apis_definition = []       # List of APIs with original argument types and extra info (e.g., const)


def get_base_type(type_str):
    if type_str.startswith("const "):
        type_str = type_str[len("const "):]
    type_str = type_str.replace(" ", "").replace("unsigned", "unsigned ").replace("*", "")
    if "[" in type_str:
        type_str = re.sub('\[\d*\]', '*', type_str)
    return type_str

def get_info(type_str):

    info = {}

    if type_str.startswith("const "):
        info["const"] = True
        info["type_clang"] = type_str[len("const "):]
    else:
        info["const"] = False
        info["type_clang"] = type_str

    # ducking ugly
    info["type_clang"] = info["type_clang"].replace(" ", "").replace("unsigned", "unsigned ").replace("*", "")
    
    # stuffs like char[100] into char*
    if "[" in info["type_clang"]:
        info["type_clang"] = re.sub('\[\d*\]', '*', info["type_clang"])

    return info

# generate an API structur from the AST node
def get_api(node):
    # {"function_name": "NotConfigured", "is_vararg": false,
    #           "return_info": {"name": "return", "flag": "val", "size": 32, "type": "i32"},
    #           "arguments_info": [{"name": "tif", "flag": "ref", "size": 64, "type": "%struct.tiff*"}, {"name": "scheme", "flag": "val", "size": 32, "type": "i32"}]}

    api_obj = {}

    function_name = node.displayname[:node.displayname.index("(")]
    api_obj["function_name"] = function_name

    nt = node.type

    rt = nt.get_result()
    rt_str = rt.spelling
    api_obj["return_info"] = get_info(rt_str)

    arguments_info = []
    for a in nt.argument_types():
        a_str = a.spelling
        info = get_info(a_str)
        arguments_info.append(copy.deepcopy(info))
    api_obj["arguments_info"] = arguments_info

    return api_obj

def find_return_and_param_types(node, function_name, output_data):
    if node.displayname.startswith(f"{function_name}(") and node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
        print(node.displayname)
        print(node.result_type.kind)

        rt = node.type.get_result()
        print(get_base_type(rt.spelling))
        output_data["return"] = {"type": get_base_type(rt.spelling)}
        return True
        # TODO: handle params
        # for a in node.type.argument_types():
        #     a_str = a.spelling
        #     print(a_str)
        # for idx, param in enumerate(children[1:]):
        #     # print(param.displayname)
        #     if list(param.get_children()):
        #         param_type = list(param.get_children())[0]
        #         output_data["params"][f"param_{idx}"] = param_type.displayname
            # print(child.displayname)
            # for ch in child.get_children():
                # print(ch.displayname)

            # print(child.type.kind)

    for child in node.get_children():
        if find_return_and_param_types(child, function_name, output_data):
            return

    # Recurse for children of this node
    # if "TIFF" == node.displayname and node.type.kind == clang.cindex.TypeKind.TYPEDEF:
    #     # print(node.displayname)
    #     # print(node.kind)
    #     # print(node.access_specifier)
    #     # print(node.type.kind)
    #     # print(node.result_type.kind)
    #     # for arg in node.get_arguments():
    #         # print(arg)
    #     for child in node.get_children():
    #         print("hello world")
    #         print(child.displayname)
    #         print(child.type.kind)
    #     # print(node.get_children()[0].displayname)
    #     return
    
    # if "tiff" == node.displayname and node.type.kind == clang.cindex.TypeKind.RECORD:
    #     # print(node.displayname)
    #     # print(node.kind)
    #     # print(node.access_specifier)
    #     # print(node.type.kind)
    #     # print(node.result_type.kind)
    #     # for arg in node.get_arguments():
    #         # print(arg)
    #     children = []
    #     for child in node.get_children():
    #         children.append(child.displayname)
    #         # print(child.displayname)
    #         # print(child.kind)
    #     # print(node.get_children()[0].displayname)
    #     if children:
    #         print(len(children))
    #         print(children[9])
    #     # print(children)
    #     return

    

    # if node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and include_folder in str(node.location.file):
    #     function_declarations.append(node)
    #     apis_definition.append(get_api(node))

    # Print out information about the node
    # if "TIFF" == node.displayname:
    #     print(node.displayname)
    # print('Found %s [line=%s, col=%s] %s' % (node.displayname, node.location.line, node.location.column, node.type))
        # from IPython import embed; embed(); exit()

    # if node.type.kind == clang.cindex.TypeKind.TYPEDEF and node.type.get_size() == -2:
    #     for child in node.get_children():
    #         if child.kind == clang.cindex.CursorKind.TYPE_REF:
    #             type_incomplete.add("%" + child.displayname.replace(" ","."))


def translate_fields(node, fields, type_name):
    fields = list(filter(lambda x: x != -1, fields))
    if not fields:
        return False, []

    if len(fields) != 1:
        return False, []
    

    if type_name == node.displayname and node.type.kind == clang.cindex.TypeKind.TYPEDEF:
        for child in node.get_children():
            succ, res = translate_fields(child, fields, type_name)
            if succ:
                return True, res
        # print(node.result_type.kind)
        # for arg in node.get_arguments():
            # print(arg)
        # for child in node.get_children():
        #     succ, res = translate_fields(child, fields, type_name)
        #     if succ:
        #         return res
        # print(node.get_children()[0].displayname)
        return True, []

    if type_name == node.displayname and node.type.kind == clang.cindex.TypeKind.RECORD:
        print(node.displayname)
        print(node.kind)
        print(node.access_specifier)
        print(node.type.kind)
        # print(node.result_type.kind)
        # for arg in node.get_arguments():
            # print(arg)
        # children = []
        # for child in node.get_children():
        #     children.append(child.displayname)
        #     # print(child.displayname)
        #     # print(child.kind)
        # # print(node.get_children()[0].displayname)
        # if children:
        #     print(len(children))
        #     print(children[9])
        # print(children)
        return True, []

    for child in node.get_children():
        succ, res = translate_fields(child, fields, type_name)
        if succ:
            return True, res

    return False, []
    # if "tiff" == node.displayname and node.type.kind == clang.cindex.TypeKind.RECORD:
    #     print(node.displayname)
    #     print(node.kind)
    #     print(node.actranslate_fieldsss_specifier)
    #     print(node.type.kind)
    #     print(node.result_type.kind)
    #     # for arg in node.get_arguments():
    #         # print(arg)
    #     # children = []
    #     # for child in node.get_children():
    #     #     children.append(child.displayname)
    #     #     # print(child.displayname)
    #     #     # print(child.kind)
    #     # # print(node.get_children()[0].displayname)
    #     # if children:
    #     #     print(len(children))
    #     #     print(children[9])
    #     # # print(children)
    #     return


def get_stub_file(include_folder):

    stub_file = tempfile.NamedTemporaryFile(suffix='.cc', delete=False).name

    # from IPython import embed; embed(); exit()

    with open(stub_file, 'w') as tmp:
        for root, subdirs, files in os.walk(include_folder):
            for h in files:
                if h.endswith(".h") or h.endswith(".h++") or h.endswith(".hh") or h.endswith(".hpp"):
                    h_path = os.path.join(root, h)
                    tmp.write(f"#include \"{h_path}\"\n")

        tmp.write("\n")

        tmp.write("int main(int argc, char** argv) {return 0;}")

    return stub_file

def _main():

    parser = argparse.ArgumentParser(description='Extract list of exprted function from header files.')
    parser.add_argument('-include_folder', '-i', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-json_file', '-j', type=str, help='Json file created by condition extractor', required=True)
    parser.add_argument('-output_file', '-o', type=str, help='Output file', required=True)

    args = parser.parse_args()

    include_folder = args.include_folder
    output_file = args.output_file
    input_file = args.json_file

    with open(input_file, 'r') as f:
        extractor_data = json.load(f)

    tmp_file = get_stub_file(include_folder)

    function_name = extractor_data[0]["functionName"]
    output_data = {}
    output_data["functionName"] = function_name
    output_data["return"] = {}
    output_data["params"] = {}


    clang.cindex.Config.set_library_file("/usr/local/lib/python3.9/dist-packages/clang/native/libclang.so")
    index = clang.cindex.Index.create()

    # Generate AST from filepath passed in the command line
    tu = index.parse(tmp_file)

    root = tu.cursor        # Get the root of the AST


    find_return_and_param_types(root, function_name, output_data)
    print(output_data)

    output_data["return"]["access"] = []
    return_access = extractor_data[0]["return"]
    for ra in return_access:
        access_type = ra["access"]
        fields = ra["fields"]
        translate_fields(root, fields, output_data["return"]["type"])
        output_data["return"]["access"].append(ra)
    # print(return_access)


    # with open(output_file, 'w') as out_f:
    #     for f in function_declarations:
    #         out_f.write(f"{f.displayname}\n")


if __name__ == "__main__":
    _main()