from bitarray import bitarray
from bitarray.util import ba2int

from CipherMachine import CipherMachine

KEY_PERMUTATION_TABLE = [
    56, 48, 40, 32, 24, 16, 8,
    0, 57, 49, 41, 33, 25, 17,
    9, 1, 58, 50, 42, 34, 26,
    18, 10, 2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
    6, 61, 53, 45, 37, 29, 21,
    13, 5, 60, 52, 44, 36, 28,
    20, 12, 4, 27, 19, 11, 3
]

NUMBER_OF_ROTATIONS = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
]

KEY_COMPRESSION_TABLE = [
    13, 16, 10, 23, 0, 4, 2, 27,
    14, 5, 20, 9, 22, 18, 11, 3,
    25, 7, 15, 6, 26, 19, 12, 1,
    40, 51, 30, 36, 46, 54, 29, 39,
    50, 44, 32, 47, 43, 48, 38, 55,
    33, 52, 45, 41, 49, 35, 28, 31
]

INITIAL_PERMUTATION = [
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16, 8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
]

FINAL_PERMUTATION = [
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
    32, 0, 40, 8, 48, 16, 56, 24
]

EXPANSION_TABLE = [
    31, 0, 1, 2, 3, 4,
    3, 4, 5, 6, 7, 8,
    7, 8, 9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31, 0
]

PERMUTATION_TABLE = [
    15, 6, 19, 20, 28, 11,
    27, 16, 0, 14, 22, 25,
    4, 17, 30, 9, 1, 7,
    23, 13, 31, 26, 2, 8,
    18, 12, 29, 5, 21, 10,
    3, 24
]

S_BOXES = [
    # S1
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],

    # S2
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],

    # S3
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],

    # S4
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],

    # S5
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],

    # S6
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],

    # S7
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],

    # S8
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def reduce(bits: bitarray, reduction_table: list[int]) -> bitarray:
    choice = bitarray()
    for i in range(len(reduction_table)):
        choice.append(bits[reduction_table[i]])
    return choice


def expend(bits: bitarray, expansion_table: list[int]) -> bitarray:
    expanded_bits = bitarray()
    for i in range(len(expansion_table)):
        expanded_bits.append(bits[expansion_table[i]])
    return expanded_bits


def permutate(bits: bitarray, permutation_table: list[int]) -> bitarray:
    permutation = bitarray()
    for i in range(len(permutation_table)):
        permutation.append(bits[permutation_table[i]])
    return permutation


def rotate(bits: bitarray, rotation: int) -> bitarray:
    first_bits = bitarray(bits[0:rotation])
    return bits[rotation:] + first_bits


def string_to_bits(string: str) -> bitarray:
    bits = bitarray()
    for character in string:
        bits += bitarray(f"{ord(character):08b}")
    return bits


def bits_to_string(bits: bitarray) -> str:
    string = ""
    _bytes = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    for byte in _bytes:
        string += chr(ba2int(byte))
    return string


class DES(CipherMachine):
    def __init__(self, text: str, key: str, verbose: bool = False):
        self.keys = None
        self.verbose = verbose
        self.generate_keys(string_to_bits(key))

        text_bits = string_to_bits(text)

        # NEEDS REWORK!
        if (len(text_bits) % 64) != 0:
            #text_bits += bitarray('0' * (64 - (len(text_bits) % 64)))
            raise ValueError("Text must be divisible by 64 bits")

        self.text = [text_bits[i:i + 64] for i in range(0, len(text_bits), 64)]

    def log(self, msg: str | None = None):
        if self.verbose:
            print(msg)

    def generate_keys(self, seed: bitarray):
        self.log(f"seed: {seed}")

        choice = reduce(seed, KEY_PERMUTATION_TABLE)

        self.keys = []
        for i in range(16):
            left: bitarray = choice[:28]
            right: bitarray = choice[28:]

            left = rotate(left, NUMBER_OF_ROTATIONS[i])
            right = rotate(right, NUMBER_OF_ROTATIONS[i])

            choice = left + right

            new_round = reduce(choice, KEY_COMPRESSION_TABLE)
            self.log(f"Key {i:2}: {new_round}")
            self.keys.append(new_round)

    def des_round(self, block: bitarray, index: int) -> bitarray:
        self.log(f"Round: {index + 1}")
        self.log(f"Block:       {block}")
        self.log(f"Key:         {self.keys[index]}")

        left = block[:32]
        right = block[32:]

        self.log(f"left:        {left}")
        self.log(f"right:       {right}")
        expansion = expend(right, EXPANSION_TABLE)
        self.log(f"expansion:   {expansion}")
        xor = expansion ^ self.keys[index]
        self.log(f"xor:         {xor}")

        choice = bitarray()
        for i in range(8):
            part = xor[i * 6:i * 6 + 6]
            temp = part[0:1] + part[5:6]
            row = ba2int(temp)
            column = ba2int(part[1:5])
            choice += bitarray(f"{S_BOXES[i][column + row * 16]:04b}")
        self.log(f"choice:      {choice}")

        permutation = permutate(choice, PERMUTATION_TABLE)
        self.log(f"permutation: {permutation}")
        result = right + (left ^ permutation)
        self.log(f"result:      {result}")
        self.log()
        return result

    def crypt(self, mode: int) -> str:
        if mode == 0:
            iteration = 0
            iteration_adjustment = 1
        else:
            iteration = 15
            iteration_adjustment = -1

        result = bitarray()
        for block in self.text:
            i = iteration
            self.log(f"Message: {block}")

            cipher = permutate(block, INITIAL_PERMUTATION)

            self.log(f"Initial permutation: {cipher}")

            for _ in range(16):
                cipher = self.des_round(cipher, i)
                i += iteration_adjustment
            cipher = cipher[32:] + cipher[:32]

            cipher = permutate(cipher, FINAL_PERMUTATION)
            result += cipher
            self.log(f"Ciphertext: {cipher}")
        return bits_to_string(result)

    def encrypt(self) -> str:
        return self.crypt(0)

    def decrypt(self) -> str:
        return self.crypt(1)

if __name__ == '__main__':
    DES("Lubenica", "HelloWor").encrypt()
