import os

from binaryninja.platform import Platform
from binaryninja.typelibrary import TypeLibrary
from binaryninja.log import log_info, log_warn
from binaryninja import user_plugin_path, core_ui_enabled

# Added for fixup
from binaryninja import PluginCommand, BackgroundTaskThread
from binaryninja.binaryview import BinaryView
from binaryninja.enums import SymbolType
from binaryninja.log import log_info, log_warn, log_error, log_debug


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


# TODO: this seems to be a bug in the binja's typelibs for elf objects
# once its fixed in core, there should be no need for this plugin to register
# a fixup like this.
class FixPltTypes(BackgroundTaskThread):
    def __init__(self, bv: BinaryView):
        super().__init__('Fixing ImportedFunctionSymbol types')
        self.bv = bv

    def run(self):
        if len(self.bv.platform.type_libraries) == 0:
            log_warn(f"No type libraries loaded for: {self.bv.platform.name}")
            return

        for sym in self.bv.get_symbols_of_type(SymbolType.ImportedFunctionSymbol):
            # log_debug(f"checking sym: {sym.name}")
            for typelib in self.bv.platform.type_libraries:
                sym_type = typelib.get_named_object(sym.name)

                # log_debug(f"Checking in typelib: {typelib}")

                if sym_type == None:
                    continue

                # log_debug(f"Found type type: {sym_type}")

                func = self.bv.get_function_at(sym.address)
                if func == None:
                    continue

                func.set_user_type(sym_type)
                log_debug("Updated sym %s at 0x%02X" % (sym.name, sym.address))

        self.bv.update_analysis_and_wait()

def run_plugin(bv: BinaryView):
    FixPltTypes(bv).start()

PluginCommand.register("binja-types",
                       "Fix function types missed by typelib",
                        run_plugin)
