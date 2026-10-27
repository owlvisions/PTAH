# PTAH Hopper headless export: run with `Hopper -y -l target -s ptah_hopper_export.py`.
# Writes {functions:[{name,entry,code}]} as JSON to $PTAH_OUT.
import json, os
doc = Document.getCurrentDocument()
seg = doc.getCurrentSegment()
funcs = []
if seg is not None:
    for i in range(min(seg.getProcedureCount(), 5000)):
        proc = seg.getProcedureAtIndex(i)
        ea = proc.getEntryPoint()
        try:
            code = proc.decompile()
        except Exception:
            code = None
        funcs.append({"name": doc.getNameAtAddress(ea) or hex(ea), "entry": hex(ea), "code": code})
out = os.environ.get("PTAH_OUT", "ptah-hopper.json")
with open(out, "w") as f:
    json.dump({"functions": funcs}, f)
