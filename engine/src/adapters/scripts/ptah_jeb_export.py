# PTAH JEB headless export: run with `jeb -c --srv2 --script=ptah_jeb_export.py target`.
# Writes {language, classes:[{name,code}]} as JSON to $PTAH_OUT.
import json, os
from com.pnfsoftware.jeb.client.api import IScript

class PtahJebExport(IScript):
    def run(self, ctx):
        prj = ctx.getEnginesContext().loadProject("ptah", ctx.getArguments()[0] if ctx.getArguments() else None)
        classes = []
        for unit in prj.findUnits("decompiler.dex") if hasattr(prj, "findUnits") else []:
            for t in unit.getDecompiledClasses()[:5000]:
                try:
                    classes.append({"name": t.getName(), "code": t.getDecompiledCode()})
                except Exception:
                    pass
        out = os.environ.get("PTAH_OUT", "ptah-jeb.json")
        with open(out, "w") as f:
            json.dump({"language": "java", "classes": classes}, f)
