//@category nanoMIPS
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.app.plugin.processors.sleigh.SleighInstructionPrototype;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ProbeFlow extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        List<String> rows = new ArrayList<>();
        PseudoDisassembler disassembler = new PseudoDisassembler(currentProgram);
        for (int i = 1; i < args.length; i++) {
            Address address = toAddr(args[i]);
            PseudoInstruction instruction = disassembler.disassemble(address);
            if (instruction == null) {
                rows.add(args[i] + "\tUNDEFINED");
                continue;
            }
            StringBuilder flows = new StringBuilder();
            for (Address flow : instruction.getFlows()) {
                if (flows.length() > 0) flows.append(',');
                flows.append(flow);
            }
            StringBuilder pcode = new StringBuilder();
            for (PcodeOp op : instruction.getPcode()) {
                if (pcode.length() > 0) pcode.append(',');
                pcode.append(op.getMnemonic());
            }
            var constructor = ((SleighInstructionPrototype) instruction.getPrototype())
                .getRootState().getConstructor();
            rows.add(args[i] + "\t" + instruction.getLength() + "\t"
                + instruction + "\t" + instruction.getFlowType() + "\t"
                + flows + "\t" + pcode + "\t"
                + constructor.getSourceFile() + ":" + constructor.getLineno());
        }
        Files.write(Path.of(args[0]), rows);
    }
}
