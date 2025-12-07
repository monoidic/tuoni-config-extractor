#!/usr/bin/env python3

import sys
import re
from dataclasses import dataclass
import argparse
from typing import Any

pattern = re.compile(r"[ABCDEFGHIJKLMNOP]{50000,}".encode())


@dataclass
class TLV:
    ident: int
    # uint32le len(data)
    data: bytes

    @staticmethod
    def from_bytes(b: bytes) -> "TLV":
        if len(b) < 5:
            raise Exception("invalid length")
        ident = b[0]
        length = int.from_bytes(b[1:5], "little")
        data = b[5 : 5 + length]
        if len(data) != length:
            raise Exception("invalid length")

        return TLV(ident, data)

    def __len__(self) -> int:
        return 5 + len(self.data)

    def to_bytes(self) -> bytes:
        ret = bytearray()
        ret.append(self.ident)
        ret.extend(int.to_bytes(len(self.data), 4, "little"))
        ret.extend(self.data)
        return bytes(ret)

    def children(self) -> list["TLV"]:
        off = 0
        ret: list[TLV] = []
        try:
            while off < len(self.data):
                child = TLV.from_bytes(self.data[off:])
                off += len(child)
                ret.append(child)
        except Exception as e:
            return []

        return ret

    def to_dict(self) -> dict[str, Any]:
        ret: dict[str, Any] = {"ident": self.ident}
        children = self.children()
        if children:
            ret["children"] = [child.to_dict() for child in children]
        else:
            ret["data"] = self.data

        return ret


config_structure = {
    "ident": 129,
    "name": "config",
    "children": [
        {"ident": 1, "name": "unknown1"},
        {"ident": 3, "name": "shellcode"},
        {"ident": 4, "name": "identifier", "type": "str"},
        {
            "ident": 5,
            "name": "httpconfigs_outer",
            "children": [
                {
                    "ident": 129,
                    "name": "httpconfigs",
                    "children": [
                        {
                            "ident": 129,
                            "name": "hosts",
                            "children": [
                                {"ident": 1, "name": "c2_host", "type": "str"},
                                {"ident": 2, "name": "sleep", "type": "int32"},
                                {
                                    "ident": 3,
                                    "name": "sleepRandom",
                                    "type": "int32",
                                },
                            ],
                        },
                        {"ident": 2, "name": "port", "type": "int32"},
                        {"ident": 3, "name": "get_path", "type": "str"},
                        {"ident": 4, "name": "post_path", "type": "str"},
                        {"ident": 5, "name": "cookie_name", "type": "str"},
                        {"ident": 6, "name": "metaprefix", "type": "str"},
                        {"ident": 7, "name": "metasuffix", "type": "str"},
                        {"ident": 8, "name": "https", "type": "int32"},
                        {"ident": 9, "name": "startTime", "type": "str"},
                        {"ident": 10, "name": "sleep", "type": "int32"},
                        {"ident": 11, "name": "sleepRandom", "type": "int32"},
                        {"ident": 13, "name": "instantResponses", "type": "int32"},
                        {"ident": 16, "name": "webproxy", "type": "str"},
                        {"ident": 17, "name": "webProxyUsername", "type": "str"},
                        {"ident": 18, "name": "webProxyPassword", "type": "str"},
                        {"ident": 19, "name": "unknown3", "type": "int32"},
                        {
                            "ident": 140,
                            "name": "headers",
                            "children": [
                                {"ident": 1, "name": "name"},
                                {"ident": 2, "name": "value"},
                            ],
                        },
                    ],
                }
            ],
        },
        {"ident": 6, "name": "unknown3", "type": "int32"},
    ],
}

type_map = {"str": bytes.decode, "int32": lambda b: int.from_bytes(b, "little")}

rsa_config_structure = {
    "ident": 140,
    "name": "rsa_config",
    "children": [
        {"ident": 1, "name": "rsa_pubkey"},
        {"ident": 2, "name": "rsa_keypair_guid"},
    ],
}


def map_tlv(t: TLV, desc: dict[str, Any]) -> Any:
    if desc.get("is_array"):
        # array
        arr_desc = desc["element"]
        print(t.children(), arr_desc)
        ret = [map_tlv_elements(tlv_child, arr_desc) for tlv_child in t.children()]
        return ret

    desc_children = desc.get("children")
    if not desc_children:
        # leaf node
        ret = t.data
        v_type = desc.get("type")
        if v_type:
            ret = type_map[v_type](ret)
        return ret

    # dict
    ret = map_tlv_elements(t, desc_children)

    return ret


def map_tlv_elements(t: TLV, elements: list[dict[str, Any]]) -> dict[str, Any]:
    ret = {}
    for child in t.children():
        for subel in elements:
            if child.ident == subel["ident"]:
                break
        else:
            raise Exception(f"unexepcted ident {child.ident}")

        name = subel["name"]
        if child.ident & 0x80:
            ret.setdefault(name, []).append(map_tlv(child, subel))
        else:
            ret[name] = map_tlv(child, subel)

    return ret


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "file_path", help="path to agent/shellcode/etc containing config"
    )
    parser.add_argument(
        "--show-sc",
        action="store_true",
        help="show shellcode (replaced with <shellcode> by default)",
    )
    parser.add_argument(
        "--show-raw",
        action="store_true",
        help="show relatively low-level TLV output",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="argument is to an extracted config structure; avoid trying to locate and decode it",
    )

    args = parser.parse_args()

    with open(args.file_path, "rb") as fd:
        raw = fd.read()

    if args.direct:
        b = raw
    else:
        match = pattern.search(raw)
        if not match:
            raise Exception("config not found in file")
        config = match.group(0).decode()

        trans = str.maketrans(
            {k: v for k, v in zip("ABCDEFGHIJKLMNOP", "0123456789ABCDEF")}
        )
        hex = config.translate(trans)

        b = bytes.fromhex(hex)

    t = TLV.from_bytes(b)

    if args.show_raw:
        td = t.to_dict()
        if not args.show_sc:
            td["children"][1]["data"] = b"<shellcode>"
        print(td)

    mapped = map_tlv(t, config_structure)

    if not args.show_sc:
        mapped["shellcode"] = b"<shellcode>"

    print(mapped)

    b = b[len(t) :]
    if b:
        t2 = TLV.from_bytes(b)
        b = b[len(t2) :]
        assert len(b) == 0

        if args.show_raw:
            t2d = t2.to_dict()
            print(t2d)
        mapped_rsa = map_tlv(t2, rsa_config_structure)
        print()
        print(mapped_rsa)


if __name__ == "__main__":
    main()
