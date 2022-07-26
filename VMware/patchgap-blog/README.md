# Scripts for porting debug symbol information

`idb2pat_riprel.py` - Modified the IDB2PAT script published by [FLARE][1] team to support 64-bit mode RIP relative addressing. In RIP relative addressing, 32-bit signed displacements (+/- 2GB) are used to reference code or data. These 4 bytes of displacement are treated as variable bytes during signature generation.

`rizzo_string.py` - Modified version of the [Rizzo][2] plugin to support only unique strings for signatures (removed code for other signature techniques).  This is mostly useful when there is enough unique strings e.g. debug messages in the target to be analysed. Rest of the signature techniques can be slow on large binaries. The aforementioned modification was done on the version of Rizzo shared in the Quarkslab’s blog post – [Reverse Engineering a VxWorks OS Based Router][3], which works on IDA Pro 7.4 and above.

`get_prototypes.py` - Dumps function prototype information from an IDB into a file as a key value pair of `function_name#function_type`. This can be imported into another IDB using `set_prototypes.py`

`set_prototypes.py` - Applies function prototype information from a file into an IDB with symbols. Make sure the types referenced by the functions are already imported into the IDB.

[1]: https://www.mandiant.com/resources/flare-ida-pro-script
[2]: https://github.com/tacnetsol/ida/tree/master/plugins/rizzo
[3]: https://blog.quarkslab.com/reverse-engineering-a-vxworks-os-based-router.html

