// Ghidra headless post script for the final static-analysis report.

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

public class ExportAnalysis extends GhidraScript {
    private static final Set<String> DANGEROUS = new HashSet<String>(Arrays.asList(
        "strcpy", "sprintf", "strncat", "strncpy", "memcpy", "sscanf",
        "execvp", "execlp", "execl", "poptParseArgvString", "fgets", "read"
    ));

    private String esc(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '"') {
                out.append('\\').append(c);
            } else if (c == '\n') {
                out.append("\\n");
            } else if (c == '\r') {
                out.append("\\r");
            } else if (c == '\t') {
                out.append("\\t");
            } else if (c < 32) {
                out.append(String.format("\\u%04x", (int)c));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    private String jsonString(String value) {
        return "\"" + esc(value) + "\"";
    }

    private String symbolName(Address address) {
        Symbol sym = getSymbolAt(address);
        if (sym != null) {
            return sym.getName(true);
        }
        Function fn = getFunctionAt(address);
        if (fn != null) {
            return fn.getName();
        }
        return address.toString();
    }

    private String simpleName(String value) {
        if (value == null) {
            return "";
        }
        int idx = Math.max(value.lastIndexOf("::"), value.lastIndexOf('.'));
        if (idx >= 0 && idx + 1 < value.length()) {
            return value.substring(idx + 1);
        }
        return value;
    }

    @Override
    public void run() throws Exception {
        String outPath = getScriptArgs().length > 0 ? getScriptArgs()[0] : "ghidra_analysis.json";
        Listing listing = currentProgram.getListing();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        LinkedHashSet<Function> interesting = new LinkedHashSet<Function>();
        StringBuilder calls = new StringBuilder();
        int functionCount = 0;
        int callCount = 0;

        while (funcs.hasNext() && !monitor.isCancelled()) {
            Function fn = funcs.next();
            functionCount++;
            InstructionIterator insts = listing.getInstructions(fn.getBody(), true);
            while (insts.hasNext() && !monitor.isCancelled()) {
                Instruction inst = insts.next();
                FlowType flow = inst.getFlowType();
                if (!flow.isCall()) {
                    continue;
                }
                for (Reference ref : inst.getReferencesFrom()) {
                    Address to = ref.getToAddress();
                    String target = symbolName(to);
                    String simple = simpleName(target);
                    if (!DANGEROUS.contains(simple)) {
                        continue;
                    }
                    if (callCount > 0) {
                        calls.append(",");
                    }
                    calls.append("{")
                         .append("\"function\":").append(jsonString(fn.getName())).append(",")
                         .append("\"function_entry\":").append(jsonString(fn.getEntryPoint().toString())).append(",")
                         .append("\"call_addr\":").append(jsonString(inst.getAddress().toString())).append(",")
                         .append("\"target\":").append(jsonString(simple)).append(",")
                         .append("\"target_full\":").append(jsonString(target)).append(",")
                         .append("\"instruction\":").append(jsonString(inst.toString()))
                         .append("}");
                    interesting.add(fn);
                    callCount++;
                }
            }
        }

        StringBuilder decompiled = new StringBuilder();
        DecompInterface ifc = new DecompInterface();
        ifc.openProgram(currentProgram);
        int decompCount = 0;
        for (Function fn : interesting) {
            if (decompCount >= 12 || monitor.isCancelled()) {
                break;
            }
            DecompileResults res = ifc.decompileFunction(fn, 60, monitor);
            String c = "";
            if (res != null && res.decompileCompleted() && res.getDecompiledFunction() != null) {
                c = res.getDecompiledFunction().getC();
            } else if (res != null) {
                c = "DECOMPILATION_FAILED: " + res.getErrorMessage();
            }
            if (decompCount > 0) {
                decompiled.append(",");
            }
            decompiled.append("{")
                      .append("\"function\":").append(jsonString(fn.getName())).append(",")
                      .append("\"entry\":").append(jsonString(fn.getEntryPoint().toString())).append(",")
                      .append("\"c\":").append(jsonString(c))
                      .append("}");
            decompCount++;
        }
        ifc.dispose();

        StringBuilder strings = new StringBuilder();
        DataIterator data = listing.getDefinedData(true);
        int stringCount = 0;
        while (data.hasNext() && stringCount < 80 && !monitor.isCancelled()) {
            Data d = data.next();
            Object value = d.getValue();
            if (!(value instanceof String)) {
                continue;
            }
            String s = (String)value;
            if (!(s.contains("dateformat") || s.contains("Date format") || s.contains("script")
                    || s.contains("compress") || s.contains("mail") || s.contains("/bin/sh"))) {
                continue;
            }
            if (stringCount > 0) {
                strings.append(",");
            }
            strings.append("{")
                   .append("\"address\":").append(jsonString(d.getAddress().toString())).append(",")
                   .append("\"value\":").append(jsonString(s))
                   .append("}");
            stringCount++;
        }

        PrintWriter out = new PrintWriter(new FileWriter(outPath));
        out.println("{");
        out.println("\"program\":\"" + esc(currentProgram.getName()) + "\",");
        out.println("\"language\":\"" + esc(currentProgram.getLanguageID().toString()) + "\",");
        out.println("\"compiler\":\"" + esc(currentProgram.getCompilerSpec().getCompilerSpecID().toString()) + "\",");
        out.println("\"function_count\":" + functionCount + ",");
        out.println("\"dangerous_call_count\":" + callCount + ",");
        out.println("\"dangerous_calls\":[" + calls.toString() + "],");
        out.println("\"interesting_strings\":[" + strings.toString() + "],");
        out.println("\"decompiled_functions\":[" + decompiled.toString() + "]");
        out.println("}");
        out.close();
        println("Exported static analysis to " + outPath);
    }
}
