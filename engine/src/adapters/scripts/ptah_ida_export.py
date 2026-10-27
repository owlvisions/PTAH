# PTAH IDA headless export: run with `idat -A -S"ptah_ida_export.py" -OPTAH_OUT:/path target`.
# Writes {functions:[{name,entry,code}], symbols:[{name,address}]} as JSON to $PTAH_OUT.
import json, os, idaapi, idautils, idc
try:
    import ida_hexrays
    ida_hexrays.init_hexrays_plugin()
except Exception:
    ida_hexrays = None
idaapi.auto_wait()
funcs = []
for ea in list(idautils.Functions())[:5000]:
    name = idc.get_func_name(ea)
    code = None
    if ida_hexrays:
        try:
            code = str(ida_hexrays.decompile(ea))
        except Exception:
            code = None
    funcs.append({"name": name, "entry": hex(ea), "code": code})
syms = [{"name": idc.get_name(ea), "address": hex(ea)} for ea, _ in idautils.Names()][:20000]
out = os.environ.get("PTAH_OUT") or (idc.ARGV[1] if len(idc.ARGV) > 1 else "ptah-ida.json")
with open(out, "w") as f:
    json.dump({"functions": funcs, "symbols": syms}, f)
idc.qexit(0)
