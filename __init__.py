import os

from binaryninja.platform import Platform
from binaryninja.typelibrary import TypeLibrary
from binaryninja.log import log_info, log_warn
from binaryninja import user_plugin_path, core_ui_enabled

# TODO: fix the create-typelib script to stop it from loading this plugin
if core_ui_enabled():
    typelib_path = os.path.join(user_plugin_path(), "binja-types", "typelib")

    for platform_name in os.listdir(typelib_path):
        cur_platform = Platform[platform_name]
        cur_dir = os.path.join(typelib_path, platform_name)

        for typelib_name in os.listdir(cur_dir):
            library_filepath = os.path.join(cur_dir, typelib_name)

            log_name = f"{platform_name}/{typelib_name}"
            log_info(f"Importing typelib: {log_name}")

            type_lib = TypeLibrary.load_from_file(library_filepath)
            cur_platform.type_libraries.append(type_lib)