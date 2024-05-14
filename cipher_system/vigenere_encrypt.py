import random
import string

def generate_random_key(length):
    return ''.join(random.choice(string.ascii_letters) for _ in range(length))

def vigenere_encrypt(key, plain_text):
    if not plain_text or not key:
        print("Invalid input parameters")
        return -1, None

    len_plain_text = len(plain_text)
    cipher_text = []

    key_len = len(key)
    range_size = 26 * 2  # considering both upper and lower case

    key_index = 0
    for i in range(len_plain_text):
        if plain_text[i].isalpha():
            if plain_text[i].islower():
                range_low = 'a'
            else:
                range_low = 'A'
            plain_offset = ord(plain_text[i]) - ord(range_low)
            key_offset = ord(key[key_index % key_len].lower()) - ord('a')
            cipher_text.append(chr((plain_offset + key_offset) % 26 + ord(range_low)))
            key_index += 1
        else:
            cipher_text.append(plain_text[i])

    cipher_text_str = ''.join(cipher_text)  # Convert list to string

    # Debugging output
    print(f"Debug: Vigenere encryption completed. Input: '{plain_text}', Key: '{key}', Output: '{cipher_text_str}'")

    return 0, cipher_text_str

def vigenere_decrypt(key, cipher_text):
    if not cipher_text or not key:
        print("Invalid input parameters")
        return -1, None

    len_cipher_text = len(cipher_text)
    plain_text = []

    key_len = len(key)
    range_size = 26 * 2  # considering both upper and lower case

    key_index = 0
    for i in range(len_cipher_text):
        if cipher_text[i].isalpha():
            if cipher_text[i].islower():
                range_low = 'a'
            else:
                range_low = 'A'
            cipher_offset = ord(cipher_text[i]) - ord(range_low)
            key_offset = ord(key[key_index % key_len].lower()) - ord('a')
            plain_text.append(chr((cipher_offset - key_offset + 26) % 26 + ord(range_low)))
            key_index += 1
        else:
            plain_text.append(cipher_text[i])

    plain_text_str = ''.join(plain_text)  # Convert list to string

    # Debugging output
    print(f"Debug: Vigenere decryption completed. Input: '{cipher_text}', Key: '{key}', Output: '{plain_text_str}'")

    return 0, plain_text_str

# Example usage
if __name__ == "__main__":
    key_length = 50
    key = generate_random_key(key_length)
    plain_text = "The Prince of Egypt is a 1998 American animated musical drama film produced by DreamWorks Animation and distributed by DreamWorks Pictures. The second feature film from DreamWorks and the first to be traditionally animated, it is an adaptation of the Book of Exodus and follows the life of Moses from being a prince of Egypt to a prophet chosen by God to carry out his ultimate destiny of leading the Hebrews out of Egypt."

    # Encrypt
    status, cipher_text = vigenere_encrypt(key, plain_text)
    if status == 0:
        print(f"Cipher text: {cipher_text}")
    else:
        print("Encryption failed.")

    # Decrypt
    status, decrypted_text = vigenere_decrypt(key, cipher_text)
    if status == 0:
        print(f"Decrypted text: {decrypted_text}")
    else:
        print("Decryption failed.")
