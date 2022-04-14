#!/usr/bin/env python3.9

import argparse, tempfile
import sys, os, re
import clang.cindex

function_calls = []             # List of AST node objects that are function calls
function_declarations = []      # List of AST node objects that are fucntion declarations

# Traverse the AST tree
def traverse(node, include_folder):

    # Recurse for children of this node
    for child in node.get_children():
        traverse(child, include_folder)

    # Add the node to function_calls
    if node.type == clang.cindex.CursorKind.CALL_EXPR:
        function_calls.append(node)

    # Add the node to function_declarations
    # if node.type == clang.cindex.CursorKind.FUNCTION_DECL:
    # if node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and str(node.location.file).startswith("./include/"):
    if node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and include_folder in str(node.location.file):
        function_declarations.append(node)

    # # Print out information about the node
    # if "TIFFGetField" in node.displayname:
    #     print(node)
    #     print('Found %s [line=%s, col=%s] %s' % (node.displayname, node.location.line, node.location.column, node.type))
    #     from IPython import embed; embed(); exit()

MAIN_STUB = "int main(int argc, char** argv) {return 0;}"

def get_stub_file(include_folder):

    stub_file = tempfile.NamedTemporaryFile(suffix='.cc', delete=False).name

    # from IPython import embed; embed(); exit()

    with open(stub_file, 'w') as tmp:
        for h in os.listdir(include_folder):
            tmp.write("#include \"{0}\"\n".format(os.path.join(include_folder, h)))

        tmp.write("\n")

        tmp.write(MAIN_STUB)

    return stub_file

def _main():

    parser = argparse.ArgumentParser(description='Extract list of exprted function from header files.')
    parser.add_argument('-include_folder', '-i', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-exported_functions', '-e', type=str, help='List of exported functions', required=True)

    args = parser.parse_args()

    include_folder = args.include_folder
    exported_functions = args.exported_functions

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
        

if __name__ == "__main__":
    _main()