//@category nanoMIPS
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.pcode.emulate.BreakCallBack;
import ghidra.pcode.pcoderaw.PcodeOpRaw;
import ghidra.program.model.address.Address;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

public class ProbeSemantics extends GhidraScript {
    private static class Crc32Reference extends BreakCallBack {
        @Override public boolean pcodeCallback(PcodeOpRaw op) {
            var state = emulate.getMemoryState();
            long value = state.getValue(op.getInput(1));
            long message = state.getValue(op.getInput(2));
            long polynomial = state.getValue(op.getInput(3));
            int bits = op.getInput(2).getSize() * 8;
            value ^= message;
            for (int bit = 0; bit < bits; bit++) {
                value = (value >>> 1) ^ ((value & 1) != 0 ? polynomial : 0);
            }
            state.setValue(op.getOutput(), value & 0xffffffffL);
            return true;
        }
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        Map<String,Address> addresses = new HashMap<>();
        List<String> constructors = Files.readAllLines(Path.of(args[0]));
        for (int i = 1; i < constructors.size(); i++) {
            String id = constructors.get(i).split("\t", 2)[0];
            addresses.put(id, toAddr(0x2000 + 8L * (i - 1)));
        }
        List<String> output = new ArrayList<>();
        output.add("case\tok\tpc\tregisters\tmemory\terror");
        List<String> cases = Files.readAllLines(Path.of(args[1]));
        for (int i = 1; i < cases.size(); i++) {
            String[] fields = cases.get(i).split("\t", -1);
            Address address = fields[1].startsWith("0x") ? toAddr(fields[1]) : addresses.get(fields[1]);
            disassemble(address);
            EmulatorHelper emulator = new EmulatorHelper(currentProgram);
            emulator.registerCallOtherCallback("crc32", new Crc32Reference());
            try {
                emulator.writeRegister(emulator.getPCRegister(), address.getOffset());
                if (!fields[2].equals("-")) {
                    for (String entry : fields[2].split(";")) {
                        String[] item = entry.split("=", 2);
                        emulator.writeRegister(item[0], Long.decode(item[1]));
                    }
                }
                if (!fields[5].equals("-")) {
                    for (String entry : fields[5].split(";")) {
                        String[] item = entry.split(":", 2);
                        emulator.writeMemory(toAddr(item[0]), HexFormat.of().parseHex(item[1]));
                    }
                }
                boolean ok = true;
                int steps = fields.length > 10 ? Integer.parseInt(fields[10]) : 1;
                for (int step = 0; step < steps && ok; step++) {
                    ok = emulator.step(monitor);
                }
                StringBuilder registers = new StringBuilder();
                if (!fields[3].equals("-")) {
                    for (String entry : fields[3].split(";")) {
                        String name = entry.split("=", 2)[0];
                        if (registers.length() > 0) registers.append(';');
                        registers.append(name).append('=').append(emulator.readRegister(name).toString(16));
                    }
                }
                StringBuilder memory = new StringBuilder();
                if (!fields[6].equals("-")) {
                    for (String entry : fields[6].split(";")) {
                        String[] item = entry.split(":", 2);
                        if (memory.length() > 0) memory.append(';');
                        memory.append(item[0]).append(':').append(HexFormat.of().formatHex(
                            emulator.readMemory(toAddr(item[0]), item[1].length() / 2)));
                    }
                }
                output.add(fields[0] + "\t" + ok + "\t"
                    + emulator.readRegister(emulator.getPCRegister()).toString(16) + "\t"
                    + registers + "\t" + memory + "\t"
                    + String.valueOf(emulator.getLastError()).replace('\t', ' '));
            } catch (Exception e) {
                output.add(fields[0] + "\tfalse\t\t\t\t" + e.toString().replace('\t', ' '));
            } finally {
                emulator.dispose();
            }
        }
        Files.write(Path.of(args[2]), output);
    }
}
