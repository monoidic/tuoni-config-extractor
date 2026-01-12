#!/usr/bin/env python3

import elftools.elf.elffile

PADSIZE = 8
SIZE_LEN = 4
DATA_OFF = PADSIZE + SIZE_LEN


def extract_config(path: str) -> bytes:
    with open(path, "rb") as fd:
        elf = elftools.elf.elffile.ELFFile(fd)
        section = elf.get_section_by_name(".myconf")
        assert section
        data = section.data()
        conf_length = int.from_bytes(data[PADSIZE:DATA_OFF], "little")
        conf_data = data[DATA_OFF : DATA_OFF + conf_length]
        conf_data = bytes(c ^ 0x7F for c in conf_data)
        return conf_data
