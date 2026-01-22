#!/usr/bin/env python3

from dataclasses import dataclass
from typing import Any


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
