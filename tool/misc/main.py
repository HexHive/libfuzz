#!/usr/bin/env python3.9

import argparse, tempfile, json
import os, re
import clang.cindex


field_names_and_types_map = {}


def get_base_type(type_str):
    if type_str.startswith("const "):
        type_str = type_str[len("const "):]
    type_str = type_str.replace(" ", "").replace("unsigned", "unsigned ").replace("*", "")
    if "[" in type_str:
        type_str = re.sub('\[\d*\]', '*', type_str)
    return type_str


def find_return_and_param_types(node, function_name):
    if node.displayname.startswith(f"{function_name}(") and node.type.kind == clang.cindex.TypeKind.FUNCTIONPROTO:
        rt = node.type.get_result()
        result = {"return": get_base_type(rt.spelling)}
        for idx, a in enumerate(node.type.argument_types()):
            a_str = get_base_type(a.spelling)
            result[f"param_{idx}"] = a_str        
        return True, result

    for child in node.get_children():
        succ, res = find_return_and_param_types(child, function_name)
        if succ:
            return True, res

    return False, {}
    

def find_field_names_and_types(node, type_name):
    if type_name in node.displayname and node.type.kind == clang.cindex.TypeKind.RECORD:
        field_names_and_types = []
        for child in node.get_children():
            children = list(child.get_children())
            if len(children) == 0:
                type = 'basic_type'
            elif len(children) == 1:
                type = children[0].displayname
            else:
                continue

            field_names_and_types.append((type if type else "other_type", child.displayname))

        if field_names_and_types:
            return True, field_names_and_types
    
    elif type_name in node.displayname and node.type.kind == clang.cindex.TypeKind.TYPEDEF:
        field_names_and_types = []
        for child in node.get_children():
            if child.kind == clang.cindex.CursorKind.STRUCT_DECL:
                for child in child.get_children():
                    children = list(child.get_children())
                    if len(children) == 0:
                        type = 'basic_type'
                    elif len(children) == 1:
                        type = children[0].displayname
                    else:
                        continue

                    field_names_and_types.append((type if type else "other_type", child.displayname))

        if field_names_and_types:
            return True, field_names_and_types

    for child in node.get_children():
        succ, res = find_field_names_and_types(child, type_name)
        if succ:
            return True, res

    return False, ""

def find_base_type(node, type):
    if type == node.displayname and node.type.kind == clang.cindex.TypeKind.TYPEDEF:
        for child in node.get_children():
            if child.displayname:
                return True, child.displayname.replace("struct ", "")
    for child in node.get_children():
        succ, res = find_base_type(child, type)
        if succ:
            return succ, res

    return False, ''

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

def add_field_names_to_function_data(root, function_data):
    function_name = function_data["functionName"]

    succ, function_types = find_return_and_param_types(root, function_name)
    if not succ:
        print(f"Could not find return and param types for function '{function_name}'")
        return False, {}
    
    for name, type in function_types.items():
        print(name)
        succ, base_type = find_base_type(root, type)
        if not succ:
            base_type = type
        
        succ, field_names_and_types = find_field_names_and_types(root, base_type)
        if not succ:
            print(f"Could not find field names and types for '{base_type}'")
            for access in function_data[name]:
                access["field_name"] = "N/A"
            continue

        field_names_and_types_map[base_type] = field_names_and_types
    

        
        
        for access in function_data[name]:
            print(access)
            access_types_list = [base_type]
            access_param_names_list = []
            fields = [field for field in access["fields"] if field != -1]
            for field_idx in fields:
                prev_field_type = access_types_list[-1]
                if prev_field_type in ["other_type", "basic_type"]:
                    continue
                if prev_field_type in field_names_and_types_map:
                    access_types_list.append(field_names_and_types_map[prev_field_type][field_idx][0])
                    access_param_names_list.append(field_names_and_types_map[prev_field_type][field_idx][1])
                else:
                    succ, field_names_and_types = find_field_names_and_types(root, prev_field_type)
                    field_names_and_types_map[prev_field_type] = field_names_and_types
                    access_types_list.append(field_names_and_types[field_idx][0])
                    access_param_names_list.append(field_names_and_types[field_idx][1])
            
            if access_param_names_list:
                access["field_name"] = access_param_names_list[-1]
            else:
                access["field_name"] = "N/A"
    return function_data


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


    clang.cindex.Config.set_library_file("/usr/local/lib/python3.9/dist-packages/clang/native/libclang.so")
    index = clang.cindex.Index.create()

    # Generate AST from filepath passed in the command line
    tu = index.parse(tmp_file)

    root = tu.cursor        # Get the root of the AST

    output = []
    for function_data in extractor_data:
        data = add_field_names_to_function_data(root, function_data)
        output.append(data)
    
    with open(output_file, "w") as out:
        json.dump(data, out, indent=4)

    

if __name__ == "__main__":
    _main()