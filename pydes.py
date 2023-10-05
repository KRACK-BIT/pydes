#!/usr/bin/env python3
# -*- coding: utf8 -*-

from enum import Enum
from typing import Optional

from bit_helpers import binvalue, bit_array_to_string, nsplit, string_to_bit_array
from des_const import CP_1, CP_2, PI, PI_1, S_BOX, SHIFT, E, P


class CipherMode(Enum):
    ENCRYPT = 1
    DECRYPT = 0


class BlockCipherDES:
    def __init__(self):
        self.password: Optional[str] = None
        self.text: Optional[str] = None
        self.round_keys = list()

    def run(self, key, text, action=CipherMode.ENCRYPT, padding=False):
        if len(key) < 8:
            raise ValueError("Key Should be 8 bytes long")
        elif len(key) > 8:
            key = key[:8]  # If key size is above 8bytes, cut to be 8bytes long

        self.password = key
        self.text = text

        if padding and action == CipherMode.ENCRYPT:
            self.addPadding()
        elif (
            len(self.text) % 8 != 0
        ):  # If not padding specified data size must be multiple of 8 bytes
            raise ValueError("Data size should be multiple of 8")

        self.generatekeys()  # Generate all the keys
        text_blocks = nsplit(
            self.text, 8
        )  # Split the text in blocks of 8 bytes so 64 bits
        result = list()
        for block in text_blocks:  # Loop over all the blocks of data
            block = string_to_bit_array(block)  # Convert the block in bit array
            block = self.permut(block, PI)  # Apply the initial permutation
            g, d = nsplit(block, 32)  # g(LEFT), d(RIGHT)
            tmp = None
            for i in range(16):  # Do the 16 rounds
                d_e = self.expand(d, E)  # Expand d to match Ki size (48bits)
                if action == CipherMode.ENCRYPT:
                    tmp = self.xor(self.round_keys[i], d_e)  # If encrypt use Ki
                else:
                    tmp = self.xor(
                        self.round_keys[15 - i], d_e
                    )  # If decrypt start by the last key
                tmp = self.substitute(tmp)  # Method that will apply the SBOXes
                tmp = self.permut(tmp, P)
                tmp = self.xor(g, tmp)
                g = d
                d = tmp
            result += self.permut(
                d + g, PI_1
            )  # Do the last permut and append the result to result
        final_res = bit_array_to_string(result)
        if padding and action == CipherMode.DECRYPT:
            return self.removePadding(
                final_res
            )  # Remove the padding if decrypt and padding is true
        else:
            return final_res  # Return the final string of data ciphered/deciphered

    def substitute(self, d_e):  # Substitute bytes using SBOX
        subblocks = nsplit(d_e, 6)  # Split bit array into sublist of 6 bits
        result = list()
        for i in range(len(subblocks)):  # For all the sublists
            block = subblocks[i]
            row = int(
                str(block[0]) + str(block[5]), 2
            )  # Get the row with the first and last bit
            column = int(
                "".join([str(x) for x in block[1:][:-1]]), 2
            )  # Column is the 2,3,4,5th bits
            val = S_BOX[i][row][
                column
            ]  # Take the value in the SBOX appropriated for the round (i)
            bin = binvalue(val, 4)  # Convert the value to binary
            result += [int(x) for x in bin]  # And append it to the resulting list
        return result

    def permut(
        self, block, table
    ):  # Permut the given block using the given table (so generic method)
        return [block[x - 1] for x in table]

    def expand(
        self, block, table
    ):  # Do the exact same thing than permut but for more clarity has been renamed
        return [block[x - 1] for x in table]

    def xor(self, t1, t2):  # Apply a xor and return the resulting list
        return [x ^ y for x, y in zip(t1, t2)]

    def generatekeys(self):  # Algorithm that generates all the keys
        self.round_keys = []
        key = string_to_bit_array(self.password)
        key = self.permut(key, CP_1)  # Apply the initial permut on the key
        g, d = nsplit(key, 28)  # Split it in to (g->LEFT),(d->RIGHT)
        for i in range(16):  # Apply the 16 rounds
            g, d = self.shift(
                g, d, SHIFT[i]
            )  # Apply the shift associated with the round (not always 1)
            tmp = g + d  # Merge them
            self.round_keys.append(
                self.permut(tmp, CP_2)
            )  # Apply the permut to get the Ki

    def shift(
        self, g: list, d: list, shift
    ) -> tuple[list, list]:  # Shift a list of the given value
        return g[shift:] + g[:shift], d[shift:] + d[:shift]

    def addPadding(self) -> None:  # Add padding to the datas using PKCS5 spec.
        if self.text is None:
            raise ValueError("No text to pad")
        pad_len: int = 8 - (len(self.text) % 8)
        self.text += pad_len * chr(pad_len)

    def removePadding(
        self, data: str
    ) -> str:  # Remove the padding of the plain text (it assume there is padding)
        pad_len: int = ord(data[-1])
        return data[:-pad_len]

    def encrypt(self, key, text, padding=False) -> str:
        return self.run(key=key, text=text, action=CipherMode.ENCRYPT, padding=padding)

    def decrypt(self, key, text, padding=False) -> str:
        return self.run(key=key, text=text, action=CipherMode.DECRYPT, padding=padding)


if __name__ == "__main__":
    key = "secret_k"
    text = "Hello wo"
    DES = BlockCipherDES()
    r: str = DES.encrypt(key=key, text=text)
    r2: str = DES.decrypt(key=key, text=r)
    print(f"Ciphered: {r}")
    print(f"Deciphered: {r2}")
    assert r2 == text
    print("Base test case holds!")
