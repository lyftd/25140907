// DecompileAt.java
// @category BinaryStaticAnalysis

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class DecompileAt extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: DecompileAt.java <address>");
        }

        String rawAddress = args[0].toLowerCase().replaceFirst("^0x", "");
        Address address = currentProgram.getAddressFactory()
            .getDefaultAddressSpace()
            .getAddress(rawAddress);
        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            function = currentProgram.getFunctionManager().getFunctionAt(address);
        }
        if (function == null) {
            throw new IllegalArgumentException("no function contains address " + args[0]);
        }

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        DecompileResults results = decompiler.decompileFunction(function, 60, monitor);

        println("=== GHIDRA_DECOMPILE_BEGIN ===");
        println("function=" + function.getName());
        println("entry=" + function.getEntryPoint());
        if (results.decompileCompleted() && results.getDecompiledFunction() != null) {
            println(results.getDecompiledFunction().getC());
        }
        else {
            println("decompile_error=" + results.getErrorMessage());
        }
        println("=== GHIDRA_DECOMPILE_END ===");
        decompiler.dispose();
    }
}

