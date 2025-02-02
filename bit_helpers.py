#!/usr/bin/env python3
# -*- coding: utf8 -*-


def nsplit(meta_list: list, n: int) -> list[list]:
    """Split a list into sublists of size `n`"""
    return [meta_list[k : k + n] for k in range(0, len(meta_list), n)]


def binvalue(val, bitsize) -> str:
    """Return the binary value as a string of the given size"""
    binval = bin(val)[2:] if isinstance(val, int) else bin(ord(val))[2:]
    if len(binval) > bitsize:
        raise ValueError("binary value larger than the expected size")
    while len(binval) < bitsize:
        binval: str = "0" + binval  # Add as many 0 as needed to get the wanted size
    return binval


def string_to_bit_array(text) -> list[int]:
    """Convert a string into a list of bits."""
    array = list()
    for char in text:
        binval = binvalue(char, 8)  # Get the char value on one byte
        array.extend([int(x) for x in list(binval)])  # Add the bits to the final list
    return array


def bit_array_to_string(array) -> str:
    """Recreate the string from the bit array."""
    res = "".join(
        [
            chr(int(y, 2))
            for y in ["".join([str(x) for x in _bytes]) for _bytes in nsplit(array, 8)]
        ]
    )
    return res
