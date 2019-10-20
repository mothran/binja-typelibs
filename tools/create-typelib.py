import os
import sys

from argparse import ArgumentParser

from binaryninja.platform import Platform
from binaryninja.architecture import Architecture
from binaryninja.typelibrary import TypeLibrary

from binaryninja.log import log_info, log_warn, log_error, log_debug, log_to_stdout, LogLevel


def main(args):
    log_to_stdout(LogLevel.InfoLog)

    if not os.path.exists(args.input_file):
        log_warn(f"input file: {args.input_file} does not exist")
        return 1

    dir_path = os.path.dirname(os.path.realpath(args.output))
    if not os.path.exists(dir_path):
        log_warn(f"Output path directory {dir_path} does not exist")
        return 1

    try:
        platform: Platform = Platform[args.platform]
    except KeyError:
        log_warn(f"'{args.platform}' is not supported binja platform")
        return 1

    with open(args.input_file) as fd:
        type_data = fd.read()

    if args.definitions:
        prepend_str = ""
        for defintion in args.definitions.split(","):
            prepend_str += f"#define {defintion} 1\n"
        type_data = "%s%s" % (prepend_str, type_data)

    types_path = [os.path.dirname(os.path.realpath(args.input_file))]

    type_res = platform.parse_types_from_source(type_data, filename=args.input_file, include_dirs=types_path)

    cur_typelib: TypeLibrary = TypeLibrary.new(Architecture[platform.arch.name], args.name)

    for name, type_obj in type_res.functions.items():
        # log_info(f"Adding function {name}")
        cur_typelib.add_named_object(name, type_obj)

    for name, type_obj in type_res.types.items():
        # log_info(f"Adding type {name}")
        cur_typelib.add_named_type(name, type_obj)

    cur_typelib.add_platform(platform)

    if args.alt_names:
        for name in args.alt_names.split(","):
            cur_typelib.add_alternate_name(name)

    if args.guid:
        cur_typelib.guid = args.guid

    cur_typelib.finalize()

    log_info(f"Wrote type library to {args.output}")
    cur_typelib.write_to_file(args.output)

    return 0

if __name__ == "__main__":
    parser = ArgumentParser(prog='Create Binary Ninja typelibrary from .c/.h file')

    parser.add_argument('-i', '--input_file',
        type=str,
        default=None,
        required=True,
        help='Path to c-header file to parse')
    parser.add_argument('-p', '--platform',
        type=str,
        default=None,
        required=True,
        help='Binary Ninja platform to use for parsing: ex "linux-x86_64"')
    parser.add_argument('-o', '--output',
        type=str,
        default=None,
        required=True,
        help='Path to output file ex: /tmp/test.bntl')
    parser.add_argument('-n', '--name',
        type=str,
        default=None,
        required=True,
        help='Name for typelibrary ex: "libc.so|kernel32.dll"')

    parser.add_argument('-a', '--alt_names',
        type=str,
        default=None,
        required=False,
        help='Alternative names used for the typelibrary, comment seperated ex: "libc.so.1,libc.so.6"')
    parser.add_argument('-g', '--guid',
        type=str,
        default=None,
        required=False,
        help='Guid to assign to the typelibrary: ex "6c873bf0-dd43-49df-8f74-d65376540758"')
    parser.add_argument('-d', '--definitions',
        type=str,
        default=None,
        required=False,
        help='List of #defines to add to the c-file before processing, comment seperated: eg: "MY_DEF,SECOND_DEF"')

    args = parser.parse_args()

    sys.exit(main(args))