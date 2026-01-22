#!/usr/bin/env python3

import pefile


def extract_config(path: str) -> bytes:
    pe = pefile.PE(path)
    (struct,) = (
        entry3.data
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries
        if str(entry.name) == "TXT"
        for entry2 in entry.directory.entries
        for entry3 in entry2.directory.entries
    )

    off = struct.struct.OffsetToData
    size = struct.struct.Size

    data = pe.get_memory_mapped_image()[off : off + size].decode()

    return decode_hex(data)


def decode_hex(s: str) -> bytes:
    trans = str.maketrans(
        {k: v for k, v in zip(b"ABCDEFGHIJKLMNOP", b"0123456789ABCDEF")}
    )
    hex = s.translate(trans)
    return bytes.fromhex(hex)
