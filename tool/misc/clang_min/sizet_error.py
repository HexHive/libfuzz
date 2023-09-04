#!/usr/bin/env python3

import os
import clang.cindex

# generate an API structure from the AST node
def analyze_api(node):
    
    api_obj = {}
    try:
        function_name = node.displayname[:node.displayname.index("(")]
    except ValueError:
        return {}
    function_name

    nt = node.type

    if function_name == "aom_uleb_encode_fixed_size":
        print(f"debug {function_name}")
        print("argument spelling:")
        print([a.spelling for a in nt.argument_types()])
        from IPython import embed; embed(); exit(1)


# Traverse the AST tree
def traverse(node, include_folder):

    # Recurse for children of this node
    for child in node.get_children():
        traverse(child, include_folder)

    if (node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO and 
        include_folder in str(node.location.file)):
        analyze_api(node)

def _main():

    tmp_file = "./min.cc"
    include_folder = "./aom/"

    print(tmp_file)

    # Eventually, tell clang.cindex where libclang.dylib is -- or else apt install and good luck
    clang.cindex.Config.set_library_file(os.path.join(os.path.expanduser('~'), ".local/lib/python3.8/site-packages/clang/native/libclang.so"))
    index = clang.cindex.Index.create()

    # Generate AST from filepath passed in the command line
    tu = index.parse(tmp_file, args=[f"-I{include_folder}"])

    root = tu.cursor        # Get the root of the AST
    traverse(root, include_folder)
        

if __name__ == "__main__":
    _main()
