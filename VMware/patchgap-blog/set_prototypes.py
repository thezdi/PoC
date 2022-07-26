import os
import idc
import ida_kernwin

typeinfo = ""

def read_typeinfo_file():
    name, extension = os.path.splitext(get_input_file_path())
    name = name + ".tinfo"

    filename = ida_kernwin.ask_file(0, name, "Enter the name of the file")

    with open(filename, "r") as f: return f.readlines()

typeinfo = read_typeinfo_file()

for types in typeinfo:
    function_name, function_type = types.split("#")
    function_address = idc.get_name_ea_simple(function_name)

    if function_address == idc.BADADDR: continue

    prototype = idc.parse_decl(function_type, idc.PT_SILENT)
    if prototype == None:
        print("Failed to apply typeinfo to %s" % (function_name))
        continue

    idc.apply_type(function_address, prototype)
