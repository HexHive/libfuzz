#!/usr/bin/env python3

from clang.cindex import *
# import clang.cindex
import sys

def fully_qualified(c):
    """ Retrieve a fully qualified function name (with namespaces)
    """
    res = c.spelling
    c = c.semantic_parent
    while c.kind != CursorKind.TRANSLATION_UNIT:
        res = c.spelling + '::' + res
        c = c.semantic_parent
    return res

def find_funcs_and_calls(tu):
    """ Retrieve lists of function declarations and call expressions in a translation unit
    """
    filename = tu.cursor.spelling
    # calls = []
    funcs = []
    for c in tu.cursor.walk_preorder():
        if c.location.file is None:
            pass
        elif c.location.file.name != filename:
            pass
        # elif c.kind == CursorKind.CALL_EXPR:
        #     calls.append(c)
        elif c.kind == CursorKind.FUNCTION_DECL:
            funcs.append(c)
    return funcs

index = Index.create()
args =  '-x c++ --std=c++11'.split()
tu = index.parse(sys.argv[1], args=args)
funcs = find_funcs_and_calls(tu)
for f in funcs:
    print(fully_qualified(f))
    for a in f.get_arguments():
        print(a.displayname)
        print(a.kind)
    print(f)