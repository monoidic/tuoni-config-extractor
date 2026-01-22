#!/usr/bin/env python3

from tlv import TLV
import argparse


def parse_tlvs(b: bytes) -> list[TLV]:
    ret = []
    while b:
        t = TLV.from_bytes(b)
        ret.append(t)
        b = b[len(t) :]

    return ret


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file_path", help="path to file containing TLV data")

    args = parser.parse_args()

    with open(args.file_path, "rb") as fd:
        raw = fd.read()

    for t in parse_tlvs(raw):
        print(t.to_dict())


if __name__ == "__main__":
    main()
