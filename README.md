# BinaryNinja typelibrary examples and tools

Contained within this codebase tools to generate typelibraries from .h files,
an example of how to auto load the typelib from the plugin codebase and a
tool for extracting function names / prototypes from .h files (like stdio.h etc).

The plugin will register all the included typelibraries at when binja is started
so they will propagate correctly when opening new files.

## Directories

### tools/

The create-all.py script will generate typelibs for all the files in types/,
creating a typelibrary for each supported platform.

The create-typelib.py tool provides a simple way to convert a .h/.c file into a
[TypeLibrary](https://api.binary.ninja/binaryninja.typelibrary.TypeLibrary.html)

extract-prototypes.py is a small experimental attempt to use llvm's AST parser to
extract function signatures from a .h file. Mostly used to extract all the
function names defined within a file.

### types/

Within the types/ directory are a few libraries implemented 'well-enough' to get
more clean function calls in the binja MLIL. They are not complete or fully defined
but should be a reasonable starting point.

I implemented libc / libdl as an examples, using definitions from the man pages because they
provide much more descriptive parameter names than the raw headers provided by glibc.

### typelib/

This is the directory containing all the generated typelibraries from create-all.py, it is
used as the datastore for the binja plugin (\_\_init\_\_.py).

## Current TODOs

- Currently PPC64 is disabled because it is not fully supported in Binja core yet and
missing some key type files.
- The create-all.py script could call the create-typelib.py code without a new process
but fetching a Platform out of the platforms creates a new handle and seems to break things.
- The libc header is incomplete but the binja devs are most likely working on a better one.
- This plugin is disabled for headless code because there is a bug in disabling user plugins
that triggers a race condition when generating new typelibs (because the core gets init'd)
- ImportAddressSymbol (aka printf@GOT) symbols have their types filled in but not
ImportedFunctionSymbol or ExternalSymbol (plt syms). This appears to be a bug in the typelib
core.