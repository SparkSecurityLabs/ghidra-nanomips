"""Deterministic nanoMIPS property vectors from ISA field layouts.

The encoding formulas below follow the nanoMIPS32 ISA manual, revision 01.01,
pages 88 (EXTW) and 92-93 (JALRC). They do not inspect SLEIGH source.
"""


def word_bytes(word):
    return (word >> 16).to_bytes(2, "little") + (word & 0xffff).to_bytes(2, "little")


def cases():
    result = []
    for shift in (0, 1, 7, 8, 15, 16, 23, 24, 30, 31):
        # EXTW: opcode[31:26], rt[25:21], rs[20:16], rd[15:11],
        # shift[10:6], 011[5:3], 111[2:0].
        word = (0b001000 << 26) | (6 << 21) | (5 << 16) | (4 << 11)
        word |= (shift << 6) | (0b011 << 3) | 0b111
        result.append((f"extw_shift_{shift}", word_bytes(word), "last_operand", shift))

    for barrier in (0, 1):
        for link in (0, 4, 31):
            for source in (1, 6, 14):
                # JALRC[32] / JALRC.HB: opcode[31:26], rt[25:21],
                # rs[20:16], variant[15:12], reserved[11:0].
                word = (0b010010 << 26) | (link << 21) | (source << 16)
                word |= barrier << 12
                flow = "COMPUTED_JUMP" if link == 0 else "COMPUTED_CALL"
                name = f"jalrc_{'hb_' if barrier else ''}link_{link}_source_{source}"
                result.append((name, word_bytes(word), "link_flow", flow))
    return result


def relocated_flows(flow_cases):
    """Relocate flow encodings; PC-relative targets retain their displacement."""
    result = []
    for index, (address, encoded, mnemonic, flow, target, op) in enumerate(flow_cases):
        for copy in range(3):
            name = f"relocated_flow_{index}_{copy}"
            result.append((name, encoded, "relocated_flow",
                           (address, mnemonic, flow, target, op)))
    return result


def relocated_decodes(instruction_cases):
    """Place every constructor fixture at two independent addresses."""
    result = []
    for index, row in enumerate(instruction_cases):
        for copy in range(2):
            result.append((f"relocated_decode_{index}_{copy}",
                           bytes.fromhex(row["bytes"]), "relocated_decode", index))
    return result
