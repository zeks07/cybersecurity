def string_to_int(text: str) -> list[int]:
    return [ord(text[i]) - 65 for i in range(len(text))]


def int_to_string(numbers: list[int]) -> str:
    return ''.join(chr(int(n) + 65) for n in numbers)


class CipherMachine:
    def encrypt(self):
        pass

    def decrypt(self):
        pass
