import ast
import math

from sympy import Matrix

from CipherMachine import *


def is_square_matrix(matrix: list[list[int]]) -> bool:
    if not isinstance(matrix, list) or not matrix:
        return False

    row_count = len(matrix)
    if row_count == 0:
        return False

    return all(isinstance(row, list) and len(row) == row_count for row in matrix)


def is_valid_string(string: str) -> bool:
    if not isinstance(string, str) or not string:
        return False

    length = len(string)
    return length > 0 and (length & (length - 1)) == 0 and all(char.isalpha() for char in string)


class HillAlgorithm(CipherMachine):
    def __init__(self, text: str, key: str):
        try:
            parsed_key = ast.literal_eval(key)
            if not is_square_matrix(parsed_key):
                raise ValueError
        except Exception as e:
            if not is_valid_string(key):
                raise ValueError("Key not valid")
            root = int(math.sqrt(len(key)))
            image = string_to_int(key)
            parsed_key = [image[i * root:(i + 1) * root] for i in range(root)]

        self.key = Matrix(parsed_key)
        padded_text = text.upper().replace(' ', '')
        if len(padded_text) % 2 != 0:
            padded_text = padded_text + "X" * (self.key.shape[0] - len(padded_text) % 2)
        self.text: list[int] = string_to_int(padded_text)

        if not all(character.isalpha() for character in text):
            raise ValueError("Text not valid")

    def _process(self, key: Matrix):
        size = key.shape[0]
        parts = [self.text[i:i + size] for i in range(0, len(self.text), size)]

        result: list[int] = []
        for group in parts:

            cipher = (Matrix(group).transpose() * key) % 26
            result.extend(int(number) for number in cipher)

        return int_to_string(result)


    def encrypt(self) -> str:
        return self._process(self.key)

    def decrypt(self) -> str:
        key_inverse = self.key.inv_mod(26)
        return self._process(key_inverse)
