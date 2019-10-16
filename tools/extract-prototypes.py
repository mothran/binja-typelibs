#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import clang.cindex
from clang.cindex import Cursor

from typing import List
from argparse import ArgumentParser

parser = ArgumentParser(prog='Extracts all function definitions from header file, eg: -i /usr/include/stdio.h')

parser.add_argument('-i', '--input',
    type=str,
    default=None,
    required=True,
    help='Input header file')

args = parser.parse_args()

function_declarations: List[Cursor] = list()
def traverse(node: Cursor):
    for child in node.get_children():
        traverse(child)

    if node.kind == clang.cindex.CursorKind.FUNCTION_DECL:
        function_declarations.append(node)

def main(args):
    index = clang.cindex.Index.create()
    opts = clang.cindex.TranslationUnit.PARSE_INCOMPLETE | clang.cindex.TranslationUnit.PARSE_SKIP_FUNCTION_BODIES

    tu = index.parse(args.input, None, None, opts)
    print(f'Translation unit: {tu.spelling}')

    traverse(tu.cursor)

    for node in function_declarations:
        result_type = node.result_type.spelling
        func_name = node.spelling

        # Broken because of size_t/int mixups and arguement names differ from man page clean names


        # output = f"{result_type} {func_name}("

        # parameter_decs = [c for c in node.get_children() if c.kind == clang.cindex.CursorKind.PARM_DECL]

        # param_strs = list()
        # for param_node in parameter_decs:
        #     param_strs.append(f"{param_node.type.spelling} {param_node.spelling}")

        # params = ', '.join(param_strs)
        # output += params

        # if node.type.is_function_variadic():
        #     output += " ... "

        # output += ");"
        # print(output)

        print(func_name)


if __name__ == "__main__":
    sys.exit(main(args))
