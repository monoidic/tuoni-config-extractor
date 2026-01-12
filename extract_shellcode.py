#!/usr/bin/env python3

import argparse
import extract_config


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("file_path", help="path to raw config")
    parser.add_argument("--out", help="file to output shellcode to")

    args = parser.parse_args()

    with open(args.file_path, "rb") as fd:
        raw = fd.read()
    tlv = extract_config.TLV.from_bytes(raw)

    encoded = tlv.to_dict()["children"][1]["data"]

    shellcode = bytes(b ^ 0x55 for b in encoded)
    if args.out:
        with open(args.out, "wb") as fd:
            fd.write(shellcode)
    else:
        print(shellcode.hex())


if __name__ == "__main__":
    main()
