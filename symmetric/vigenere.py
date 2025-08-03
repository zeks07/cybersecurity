from CipherMachine import *


class Vigenere(CipherMachine):
    alphabet = ['A', 'B', 'C', 'D', 'E',
                'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O',
                'P', 'Q', 'R', 'S', 'T',
                'U', 'V', 'W', 'X', 'Y', 'Z']

    def __init__(self, text: str, key: str):
        self.text = [ord(character) for character in text.upper().replace(' ', '')]
        self.key = [ord(character) for character in key.upper().replace(' ', '')]

    def encrypt(self) -> str:
        result = ""
        for i in range(len(self.text)):
            result += self.alphabet[(self.key[i % len(self.key)] + self.text[i]) % 26]
        return result

    def decrypt(self) -> str:
        result = ""
        for i in range(len(self.text)):
            result += self.alphabet[(self.text[i] - self.key[i % len(self.key)]) % 26]
        return result


class AutoKey(Vigenere):
    def __init__(self, text: str, key: str):
        super().__init__(text, key)

    def encrypt(self) -> str:
        result = ""
        for i in range(len(self.text)):
            result += self.alphabet[(self.key[i] + self.text[i]) % 26]
            self.key.append(self.text[i])
        return result

    def decrypt(self) -> str:
        result = ""
        for i in range(len(self.text)):
            next_character = self.alphabet[(self.text[i] - self.key[i]) % 26]
            result += next_character
            self.key.append(ord(next_character))
        return result
