// Ghidra headless postscript: emit decompiled functions + symbols as JSON.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class PtahExport extends GhidraScript {
  static String esc(String s){ if(s==null) return ""; StringBuilder b=new StringBuilder();
    for(char c: s.toCharArray()){ if(c=='"'||c=='\\') b.append('\\').append(c);
      else if(c=='\n') b.append("\\n"); else if(c=='\r') b.append("\\r"); else if(c=='\t') b.append("\\t");
      else if(c<0x20) b.append(String.format("\\u%04x",(int)c)); else b.append(c);} return b.toString(); }
  public void run() throws Exception {
    String out = System.getenv("PTAH_OUT");
    int maxFns = Integer.parseInt(System.getenv().getOrDefault("PTAH_MAX_FUNCS","500"));
    DecompInterface di = new DecompInterface();
    di.openProgram(currentProgram);
    PrintWriter w = new PrintWriter(new FileWriter(out));
    w.print("{\"program\":\""+esc(currentProgram.getName())+"\",");
    w.print("\"language\":\""+esc(currentProgram.getLanguageID().getIdAsString())+"\",\"functions\":[");
    FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
    int n=0; boolean first=true;
    while(it.hasNext() && n<maxFns){ Function f=it.next();
      DecompileResults r = di.decompileFunction(f, 30, monitor);
      String code = (r!=null && r.decompileCompleted()) ? r.getDecompiledFunction().getC() : null;
      if(!first) w.print(","); first=false; n++;
      w.print("{\"name\":\""+esc(f.getName())+"\",\"entry\":\""+f.getEntryPoint()+"\",");
      w.print("\"size\":"+f.getBody().getNumAddresses()+",\"external\":"+f.isExternal());
      if(code!=null) w.print(",\"code\":\""+esc(code)+"\"");
      w.print("}"); }
    w.print("],\"functionCount\":"+n+",");
    w.print("\"symbols\":[");
    SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);
    int m=0; first=true;
    while(si.hasNext() && m<5000){ Symbol s=si.next(); if(!s.isPrimary()) continue;
      if(!first) w.print(","); first=false; m++;
      w.print("{\"name\":\""+esc(s.getName())+"\",\"address\":\""+s.getAddress()+"\",\"type\":\""+esc(s.getSymbolType().toString())+"\"}"); }
    w.print("]}"); w.close(); di.dispose();
  }
}
