"""Deterministic nanoMIPS property vectors from ISA field layouts.

The encoding formulas below follow the nanoMIPS32 ISA manual, revision 01.01,
pages 88 (EXTW) and 92-93 (JALRC). They do not inspect SLEIGH source.
"""


def word_bytes(word):
    return (word >> 16).to_bytes(2, "little") + (word & 0xffff).to_bytes(2, "little")


def addiupc_scenarios():
    """PC-relative address vectors from nanoMIPS32 ISA manual, page 29."""
    displacements32 = (0, 2, -2, 0x1ffffe, -0x200000)
    displacements48 = (0, 2, -2, 0x12345678, -0x80000000)
    for bits, displacements in ((32, displacements32), (48, displacements48)):
        for offset in displacements:
            if bits == 32:
                encoded = word_bytes((1 << 26) | (6 << 21)
                                     | (offset & 0x1ffffe) | ((offset >> 21) & 1))
            else:
                encoded = ((0b011000 << 10) | (6 << 5) | 3).to_bytes(2, "little")
                encoded += (offset & 0xffff).to_bytes(2, "little")
                encoded += ((offset >> 16) & 0xffff).to_bytes(2, "little")
            yield bits, offset, encoded


def jalrc_overlap_scenarios():
    """Read the target before writing an overlapping link register."""
    for register, number in (("a0", 4), ("ra", 31)):
        for barrier in (0, 1):
            word = (0b010010 << 26) | (number << 21) | (number << 16)
            yield (f"jalrc_overlap_{register}_{barrier}",
                   word_bytes(word | (barrier << 12)), register)
    halfword = (0b110110 << 10) | (31 << 5) | (1 << 4)
    yield "jalrc_overlap_ra_16", halfword.to_bytes(2, "little"), "ra"


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


def extw_scenarios():
    """Extract the low word of the ISA's shifted 64-bit concatenation."""
    inputs = ((0x89abcdef, 0x01234567), (0xffffffff, 0x80000000))
    for _, encoded, kind, shift in cases():
        if kind != "last_operand":
            continue
        for rs, rt in inputs:
            expected = (((rt << 32) | rs) >> shift) & 0xffffffff
            yield encoded, shift, rs, rt, expected


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


def branch_offset_scenarios(instruction_cases):
    """Encode branch displacements from nanoMIPS32 ISA bit layouts."""
    fixtures = {row["constructor"]: row for row in instruction_cases}
    forms = (
        ("nanomips.sinc:991", "lo12", (-2048, -2, 0, 2, 2046)),
        ("nanomips.sinc:1034", "lo15", (-16384, -2, 0, 2, 16382)),
        ("nanomips.sinc:1061", "hi8", (-128, -2, 0, 2, 126)),
        ("nanomips.sinc:1025", "hi11", (-1024, -2, 0, 2, 1022)),
        ("nanomips.sinc:1043", "u5", (2, 4, 16, 30)),
        ("nanomips.sinc:1018", "hilo26", (-33554432, -2, 0, 2, 33554430)),
        ("nanomips.sinc:2300", "hilo22", (-2097152, -2, 0, 2, 2097150)),
    )
    for constructor, form, offsets in forms:
        fixture = fixtures[constructor]
        raw = bytes.fromhex(fixture["bytes"])
        base_hi = int.from_bytes(raw[:2], "little")
        base_lo = int.from_bytes(raw[2:], "little") if len(raw) == 4 else 0
        for offset in offsets:
            if form == "lo12":
                hi, lo = base_hi, (base_lo & ~0x7ff) | (offset & 0x7fe) | ((offset >> 11) & 1)
            elif form == "lo15":
                hi, lo = base_hi, (base_lo & ~0x3fff) | (offset & 0x3ffe) | ((offset >> 14) & 1)
            elif form == "hi8":
                hi, lo = (base_hi & ~0x7f) | (offset & 0x7e) | ((offset >> 7) & 1), 0
            elif form == "hi11":
                hi, lo = (base_hi & ~0x3ff) | (offset & 0x3fe) | ((offset >> 10) & 1), 0
            elif form == "u5":
                hi, lo = (base_hi & ~0xf) | ((offset >> 1) & 0xf), 0
            else:
                width = 26 if form == "hilo26" else 22
                mask = 0x1ff if width == 26 else 0x1f
                hi = (base_hi & ~mask) | ((offset >> 16) & mask)
                lo = (offset & 0xfffe) | ((offset >> (width - 1)) & 1)
            encoded = hi.to_bytes(2, "little")
            if len(raw) == 4:
                encoded += lo.to_bytes(2, "little")
            yield (f"branch_{form}_{offset}", encoded, "branch_target",
                   (fixture["mnemonic"], fixture["flow"], offset))


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


def rotx_reference(value, shift, shiftx, stripe):
    """ROTX bit network from nanoMIPS32 ISA manual, revision 01.01, page 160."""
    previous = value | (value << 32)
    for distance, limit, selector in ((16, 47, 8), (8, 39, 4),
                                      (4, 35, 2), (2, 33, 1), (1, 32, 0)):
        result = previous
        for bit in range(limit):
            selected = (shift if selector == 0 or bit & selector else shiftx)
            if distance == 16 and stripe and not bit & 4:
                selected = ~selected
            if selected & distance:
                source = (previous >> (bit + distance)) & 1
                result = (result & ~(1 << bit)) | (source << bit)
        previous = result
    return previous & 0xffffffff


def rotx_scenarios():
    parameters = ((0, 0, 0), (1, 8, 0), (4, 12, 1), (28, 4, 0),
                  (17, 10, 0), (31, 30, 1), (5, 6, 1))
    inputs = (0x01234567, 0x89abcdef)
    for shift, shiftx, stripe in parameters:
        word = ((0b100000 << 26) | (4 << 21) | (12 << 16) | (0b1101 << 12)
                | ((shiftx // 2) << 7) | (stripe << 6) | shift)
        encoded = word_bytes(word)
        for value in inputs:
            yield encoded, value, rotx_reference(value, shift, shiftx, stripe), (shift, shiftx, stripe)


def rotate_reference(value, amount):
    amount &= 31
    return ((value >> amount) | (value << (32 - amount))) & 0xffffffff


def rotate_scenarios():
    # Instruction fields from the ISA manual; fixed registers match the fixtures.
    immediate = (0b100000 << 26) | (5 << 21) | (5 << 16) | (0b1100 << 12) | (0b0110 << 5) | 1
    variable = (0b001000 << 26) | (20 << 16) | (25 << 11) | (0b0011010 << 3)
    for amount in (0, 1, 7, 16, 31):
        encoded = word_bytes((immediate & ~31) | amount)
        for value in (0x01234567, 0x80000001):
            yield encoded, "ROTR", f"a1={value:#x}", f"a1={rotate_reference(value, amount):#x}", amount
    encoded = word_bytes((variable & ~(31 << 21)) | (5 << 21))
    for amount in (0, 1, 31, 32, 33, 0xffffffff):
        for value in (0x01234567, 0x80000001):
            yield encoded, "ROTRV", f"s4={value:#x};a1={amount:#x}", f"t9={rotate_reference(value, amount):#x}", amount


def register_scenarios():
    cases = (("sov_pos_overflow", "nanomips.sinc:3381", "a1=0x7fffffff;a2=1", "a0=1"),
             ("sov_neg_overflow", "nanomips.sinc:3381", "a1=0x80000000;a2=0xffffffff", "a0=1"),
             ("sov_no_overflow", "nanomips.sinc:3381", "a1=1;a2=2", "a0=0"),
             ("sov_opposite_signs", "nanomips.sinc:3381", "a1=0x80000000;a2=0x7fffffff", "a0=0"))
    for name, constructor, registers_in, registers_out in cases:
        yield {"case": name, "constructor": constructor,
               "registers_in": registers_in, "registers_out": registers_out,
               "pc": "next", "memory_in": "-", "memory_out": "-",
               "status": "pass", "current_registers": "-", "current_memory": "-"}
    aliases = (("BITREVB", "nanomips.sinc:1107", "a1", "a0", 7, 8, 1),
               ("BITREVH", "nanomips.sinc:1134", "a1", "a0", 15, 16, 0),
               ("BITREVW", "nanomips.sinc:1157", "s3", "a1", 31, 0, 0),
               ("BYTEREVH", "nanomips.sinc:1280", "a1", "a0", 8, 24, 0),
               ("BYTEREVW", "nanomips.sinc:1290", "a1", "a1", 24, 8, 0))
    for mnemonic, constructor, source, destination, shift, shiftx, stripe in aliases:
        for index, value in enumerate((0x01234567, 0x89abcdef)):
            yield {"case": f"{mnemonic.lower()}_reference_{index}",
                   "constructor": constructor, "registers_in": f"{source}={value:#x}",
                   "registers_out": f"{destination}={rotx_reference(value, shift, shiftx, stripe):#x}",
                   "pc": "next", "memory_in": "-", "memory_out": "-",
                   "status": "pass", "current_registers": "-", "current_memory": "-"}
