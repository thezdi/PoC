import os
import idc
import ida_kernwin
import idaapi
import idautils

typeinfo = ""

def write_typeinfo_file(typeinfo):
    name, extension = os.path.splitext(get_input_file_path())
    name = name + ".tinfo"

    filename = ida_kernwin.ask_file(1, name, "Enter the name of the file")

    with open(filename, "wb") as f: f.write(typeinfo)

for function in idautils.Functions():
    function_name = idc.get_name(function)
    function_type = idaapi.print_type(function, True)

    if function_type == None: continue
    if function_name.startswith("sub_"): continue
    if function_name.startswith("."): continue

    typeinfo += "%s#%s" % (function_name, function_type)

write_typeinfo_file(typeinfo)
