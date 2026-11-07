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
            for source in (1, 6, 14, 31):
                # JALRC[32] / JALRC.HB: opcode[31:26], rt[25:21],
                # rs[20:16], variant[15:12], reserved[11:0].
                word = (0b010010 << 26) | (link << 21) | (source << 16)
                word |= barrier << 12
                flow = ("TERMINATOR" if link == 0 and source == 31 else
                        "COMPUTED_JUMP" if link == 0 else "COMPUTED_CALL")
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


def crc32_scenarios():
    """CRC operations from nanoMIPS32 ISA manual, pages 70-75."""
    forms = (
        ("CRC32B", "nanomips.sinc:1342", 8, 0xedb88320),
        ("CRC32CB", "nanomips.sinc:1351", 8, 0x82f63b78),
        ("CRC32CH", "nanomips.sinc:1360", 16, 0x82f63b78),
        ("CRC32CW", "nanomips.sinc:1369", 32, 0x82f63b78),
        ("CRC32H", "nanomips.sinc:1378", 16, 0xedb88320),
        ("CRC32W", "nanomips.sinc:1387", 32, 0xedb88320),
    )
    inputs = ((0, 0), (0xffffffff, 0), (0, 0xffffffff),
              (0x13579bdf, 0x2468ace0))
    for mnemonic, constructor, bits, polynomial in forms:
        for index, (seed, message) in enumerate(inputs):
            value = seed ^ (message & ((1 << bits) - 1))
            for _ in range(bits):
                value = (value >> 1) ^ (polynomial if value & 1 else 0)
            yield {
                "case": f"{mnemonic.lower()}_generated_{index}",
                "constructor": constructor,
                "registers_in": f"a0={seed:#x};a1={message:#x}",
                "registers_out": f"a0={value & 0xffffffff:#x}",
                "pc": "next", "memory_in": "-", "memory_out": "-",
                "status": "pass", "current_registers": "-", "current_memory": "-",
            }
