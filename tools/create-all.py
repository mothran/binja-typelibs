import os
import sys
import uuid
from subprocess import call

from binaryninja.platform import Platform
from binaryninja import user_plugin_path

SUPPORTED_VARIADIC = ["x86"]

TYPELIBS = [
    {
        "input_file": "libc.h",
        "output_file": "libc.bntl",
        "name": "libc.so",
        "alt_names": "libc.so.6",
        "os": "linux"
    },
    {
        "input_file": "libdl.h",
        "output_file": "libdl.bntl",
        "name": "libdl.so",
        "alt_names": "libdl.so.2",
        "os": "linux"
    }
]


def main():
    plugin_path = os.path.join(user_plugin_path(), "binja-types")
    typelib_path = os.path.join(plugin_path, "typelib")
    types_path = os.path.join(plugin_path, "types")

    platform_list = list(Platform)

    for typelib_desc in TYPELIBS:
        for platform in platform_list:
            if typelib_desc["os"] != platform.name.split("-")[0]:
                continue

            if platform.arch.name == "ppc64" or platform.arch.name ==  "ppc64_le":
                print("Skipping PPC64, not currently finished in core")
                continue

            if "archs" in typelib_desc:
                if not platform.arch.name in typelib_desc["archs"]:
                    print(f"Skipping arch {platform.arch.name}, typelib does not support it")
                    continue

            platform_dir = os.path.join(typelib_path, platform.name)
            if not os.path.exists(platform_dir):
                os.mkdir(platform_dir)

            input_file = os.path.join(types_path, typelib_desc["input_file"])
            output_file = os.path.join(platform_dir, typelib_desc["output_file"])

            definitions = None
            if platform.arch.name in SUPPORTED_VARIADIC:
                definitions = "SUPPORTED_VARIADIC"

            # Using subprocess calls for each create_typelib, because using __getitem__ on Platform causes
            # binary ninja to init a handle and causes a quite a few problems, like duplicate logging.

            call_args = ["python3", os.path.join(plugin_path, "tools", "create-typelib.py"),
                        "-i", input_file, "-o", output_file,
                        "-p", platform.name,
                        "-n", typelib_desc["name"],
                        "-a", typelib_desc["alt_names"],
                        "-g", str(uuid.uuid4())]

            if definitions:
                call_args.append("-d")
                call_args.append(definitions)

            # Currently broken? I still see the user plugins loaded
            new_env = os.environ.copy()
            new_env["BN_DISABLE_USER_PLUGINS"] = "1"

            print(f'creating typelib {typelib_desc["input_file"]} for platform: {platform.name}')
            call(call_args, env=new_env)


if __name__ == "__main__":
    sys.exit(main())