#!/usr/bin/env python3.9

import argparse, tempfile, json, copy
import sys, os, re
import clang.cindex


function_declarations = [] # List of AST node objects that are fucntion declarations
type_incomplete = set()    # List of incomplete types
apis_definition = []       # List of APIs with original argument types and extra info (e.g., const)

def get_info(type_str):

    info = {}

    if type_str.startswith("const "):
        info["const"] = True
        info["type_clang"] = type_str[len("const "):]
    else:
        info["const"] = False
        info["type_clang"] = type_str

    # ducking ugly
    info["type_clang"] = info["type_clang"].replace(" ", "").replace("unsigned", "unsigned ")
    
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

# Traverse the AST tree
def traverse(node, include_folder):

    # Recurse for children of this node
    for child in node.get_children():
        traverse(child, include_folder)

    # if node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and str(node.location.file).startswith("./include/"):
    if node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and include_folder in str(node.location.file):
        function_declarations.append(node)
        apis_definition.append(get_api(node))

    # # Print out information about the node
    # if "TIFF" == node.displayname:
    # #     print(node.displayname)
    # # print('Found %s [line=%s, col=%s] %s' % (node.displayname, node.location.line, node.location.column, node.type))
    #     from IPython import embed; embed(); exit()

    if node.type.kind == clang.cindex.TypeKind.TYPEDEF and node.type.get_size() == -2:
        for child in node.get_children():
            if child.kind == clang.cindex.CursorKind.TYPE_REF:
                type_incomplete.add("%" + child.displayname.replace(" ","."))

MAIN_STUB = "int main(int argc, char** argv) {return 0;}"

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

        tmp.write(MAIN_STUB)

    return stub_file

def _main():

    parser = argparse.ArgumentParser(description='Extract list of exprted function from header files.')
    parser.add_argument('-include_folder', '-i', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-exported_functions', '-e', type=str, help='List of exported functions', required=True)
    parser.add_argument('-incomplete_types', '-t', type=str, help='List of incomplete types', required=True)
    parser.add_argument('-apis_list', '-a', type=str, help='List of APIs with types from the AST', required=True)

    args = parser.parse_args()

    include_folder = args.include_folder
    exported_functions = args.exported_functions
    incomplete_types = args.incomplete_types
    apis_list = args.apis_list

    tmp_file = get_stub_file(include_folder)

    print(tmp_file)

    # exit()

    # Eventually, tell clang.cindex where libclang.dylib is -- or else apt install and good luck
    # clang.cindex.Config.set_library_path("/Users/tomgong/Desktop/build/lib")
    index = clang.cindex.Index.create()

    # Generate AST from filepath passed in the command line
    tu = index.parse(tmp_file)

    root = tu.cursor        # Get the root of the AST
    traverse(root, include_folder)

    with open(exported_functions, 'w') as out_f:
        for f in function_declarations:
            out_f.write(f"{f.displayname}\n")

    with open(incomplete_types, 'w') as out_f:
        for t in type_incomplete:
            out_f.write(f"{t}\n")

    with open(apis_list, 'w') as out_f:
        for a in apis_definition:
            out_f.write(f"{json.dumps(a)}\n")

        

if __name__ == "__main__":
    _main()