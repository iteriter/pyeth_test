import secrets
import hashlib
import binascii

# Work in progress, unfunctional

WORDLIST_DIR = "wordlist"

class BIP39DictException(Exception):
    pass


class Mnemonic:
    """Class for construction of BIP39 mnemonic-encoded private key for blockchain account"""
    allowed_complexity = (128, 160, 192, 224, 256)
    languages = ("english",)

    def __init__(self, complexity=128, language="English"):
        pass

    @staticmethod
    def generate_mnemonic(self, complexity, language):
        if complexity not in self.allowed_complexity:
            raise ValueError("According to BIP39 number of bits for mnemonic generation,"
                             "k, must be multiple of 32 and 128 <= k <= 256")
        if language.lower() not in self.languages:
            raise ValueError("Unsupported language. List of available languages: ", self.languages)

        self.complexity = complexity
        self.language = language

    def construct_mnemonic(self, indexes):
        """
        Take list of integer indexes, where index i is 0 <= i < 2048
        Get corresponding words from bip39 dictionary for given language, located at WORDLIST_DIR/{language}.txt
        Return mnemonic string constructed from indexed words
        """
        language = self.language
        mnemonic = []

        try:
            with open(language + ".txt", "r") as f:
                dictionary = f.readlines()
                if len(dictionary) < 2048:
                    raise BIP39DictException("Dictionary file for {lang} at {file_path} contains less than 2048 words"
                                             .format(lang=language, file_path=WORDLIST_DIR+language+".txt"))
                for index in indexes:
                    mnemonic.append(dictionary[index].strip())
        except FileNotFoundError:
            raise FileNotFoundError("Dictionary not found for {lang} language. Please make sure you have"
                                    "dictionary for this language under {file_path} in the script directory."
                                    .format(lang=language, file_path=WORDLIST_DIR+language+".txt"))

        return ' '.join(mnemonic)

    def generate_entropy(self):
        pass






















def generate_entropy(k: int):
    """
    Generate initial entropy of length k bits for bip39 mnemonic generation.
    k must be integer multiple of 32; 128 <= k <= 256
    """
    allowed_length = (128, 160, 192, 224, 256)
    assert(k in allowed_length)

    entropy = secrets.token_bytes(k // 8)

    checksum_len = k // 32
    checksum = hashlib.sha3_256(entropy).digest()[:checksum_len]

    mnemonic_num = entropy + checksum
    print(entropy, checksum, mnemonic_num)
    print(mnemonic_num, len(mnemonic_num), len(mnemonic_num) / 11)
    word_indexes = (mnemonic_num[i*11:(i+1)*11] for i in range(len(mnemonic_num) // 11))
    print(word_indexes)

generate_entropy(128)