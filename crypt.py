import argparse

from block.des import DES
from symmetric.hill import HillAlgorithm
from symmetric.vigenere import Vigenere, AutoKey


def main():
    parser = argparse.ArgumentParser(
        prog='Hill',
        description='Hill Algorithm',
        epilog='Example: python hill.py'
    )
    parser.add_argument('-e', '--encrypt', action='store_true',
                        help='Encrypt text. If not set program will decipher instead.')
    parser.add_argument('-t', '--text', required=True, type=str, help='Text to encrypt')
    parser.add_argument('-k', '--key', required=True, type=str, help='Key')
    parser.add_argument('-v', '--verbose', action='store_true')

    parser.add_argument(
        '-u',
        '--using',
        choices=['hill', 'vigenere', 'auto-key', "des"],
        required=True
    )

    args = parser.parse_args()

    text: str = args.text
    key: str = args.key

    verbose: bool = args.verbose

    cipher_machine = None

    match args.using:
        case 'hill':
            cipher_machine = HillAlgorithm(text, key)
        case 'vigenere':
            cipher_machine = Vigenere(text, key)
        case 'auto-key':
            cipher_machine = AutoKey(text, key)
        case 'des':
            print("WARNING: Some terminals might delete invisible characters!")
            cipher_machine = DES(text, key, verbose)

    if args.encrypt:
        print(cipher_machine.encrypt())
    else:
        print(cipher_machine.decrypt())


if __name__ == '__main__':
    main()
