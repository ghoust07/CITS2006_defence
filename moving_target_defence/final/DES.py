import random
import string

# Generate a random key of length 50 characters
def generate_key():
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=50))

# Save the key to a file
def save_key(cipher, key):
    with open('RBaEncryptionKeys.txt', 'a', encoding='utf-8') as f:
        f.write(f"{cipher}:{key}\n")

# Load the key from a file, generating a new one if not found
def load_key(cipherkeyset):
    try:
        with open('RBaEncryptionKeys.txt', 'r+', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 2:
                    cipher, key = parts
                    if cipher == cipherkeyset:
                        return key
        # If the cipherkeyset is not found, generate a new key and save it
        key = generate_key()
        save_key(cipherkeyset, key)
        return key
    except FileNotFoundError:
        # If the file doesn't exist, create it and return a new generated key
        key = generate_key()
        save_key(cipherkeyset, key)
        return key

# Initial Permutation Table
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation Table
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion Table
E = [32, 1, 2, 3, 4, 5, 4, 5,
     6, 7, 8, 9, 8, 9, 10, 11,
     12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21,
     22, 23, 24, 25, 24, 25, 26, 27,
     28, 29, 28, 29, 30, 31, 32, 1]

# S-boxes
S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Permutation Table
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Permuted Choice 1 Table
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 Table
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Rotation Schedule Table
ROTATIONS = [1, 1, 2, 2, 2, 2, 2, 2,
             1, 2, 2, 2, 2, 2, 2, 1]

# Permute function
def permute(block, table):
    return [(block[i - 1] % len(table)) for i in table]

# Left rotation function
def rotate_left(block, n):
    return block[n:] + block[:n]

# Key schedule function
def key_schedule(key):
    key = permute(key, PC1)
    left, right = key[:28], key[28:]
    round_keys = []
    for i in range(16):
        left = rotate_left(left, ROTATIONS[i])
        right = rotate_left(right, ROTATIONS[i])
        round_keys.append(permute(left + right, PC2))
    return round_keys

# XOR function
def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

# S-box substitution function
def s_box_substitution(block):
    sub_blocks = [block[i * 6:(i + 1) * 6] for i in range(8)]
    result = []
    for i, s_block in enumerate(S_BOX):
        row = int(f"{sub_blocks[i][0]}{sub_blocks[i][5]}", 2)
        col = int(''.join(map(str, sub_blocks[i][1:5])), 2)
        result += list(map(int, f"{s_block[row][col]:04b}"))
    return result

# Function for a single round of DES encryption
def des_round(left, right, round_key):
    right_expanded = permute(right, E)
    xor_result = xor(right_expanded, round_key)
    substituted = s_box_substitution(xor_result)
    permuted = permute(substituted, P)
    return right, xor(left, permuted)

# Function to encrypt a single block using DES
def des_encrypt_block(block, round_keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for round_key in round_keys:
        left, right = des_round(left, right, round_key)
    cipher_block = permute(right + left, FP)
    return cipher_block

# Function to decrypt a single block using DES
def des_decrypt_block(block, round_keys):
    block = permute(block, IP)
    left, right = block[:32], block[32:]
    for round_key in reversed(round_keys):
        left, right = des_round(left, right, round_key)
    plain_block = permute(right + left, FP)
    return plain_block

# Convert text to bits
def text_to_bits(text):
    bits = [int(bit) for char in text for bit in f"{ord(char):08b}"]
    # Add padding if necessary
    padding_length = (8 - len(bits) % 8) % 8
    bits.extend([0] * padding_length)
    return bits

# Convert bits to text
def bits_to_text(bits):
    # Remove padding
    while len(bits) % 8 != 0:
        bits.pop()
    chars = [chr(int(''.join(map(str, bits[i:i + 8])), 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

# DES encryption function
def des_encrypt(key, plain_text):
    key_bits = text_to_bits(key)
    round_keys = key_schedule(key_bits)
    plain_bits = text_to_bits(plain_text)
    cipher_bits = des_encrypt_block(plain_bits, round_keys)
    return bits_to_text(cipher_bits)

# DES decryption function
def des_decrypt(key, cipher_text):
    key_bits = text_to_bits(key)
    round_keys = key_schedule(key_bits)
    cipher_bits = text_to_bits(cipher_text)
    plain_bits = des_decrypt_block(cipher_bits, round_keys)
    return bits_to_text(plain_bits)

# Function to perform DES encryption on a file
def DES_ENCRYPTION(file, key):
    with open(file, 'r', encoding='utf-8') as f:
        plain_text = f.read()

    # Split plaintext into blocks of 64 bits and pad if necessary
    blocks = [plain_text[i:i+8] for i in range(0, len(plain_text), 8)]
    blocks = [block.ljust(8, '\0') for block in blocks]  # Pad with null characters

    # Encrypt each block individually
    encrypted_blocks = [des_encrypt(key, block) for block in blocks]

    # Concatenate encrypted blocks
    cipher_text = ''.join(encrypted_blocks)

    # Write the result back to the file
    with open(f"{file}", 'w', encoding='utf-8') as f:
        f.write(cipher_text)

# Function to perform DES decryption on a file
def DES_DECRYPTION(file, key):
    with open(file, 'r', encoding='utf-8') as f:
        cipher_text = f.read()

    # Split ciphertext into blocks of 64 bits and pad if necessary
    blocks = [cipher_text[i:i+8] for i in range(0, len(cipher_text), 8)]
    blocks = [block.ljust(8, '\0') for block in blocks]  # Pad with null characters

    # Decrypt each block individually
    decrypted_blocks = [des_decrypt(key, block) for block in blocks]

    # Concatenate decrypted blocks
    plain_text = ''.join(decrypted_blocks)

    # Write the result back to the file
    with open(f"{file}", 'w', encoding='utf-8') as f:
        f.write(plain_text)

def des_cipher(file, cipherkeyset, EncryptorDecrypt):
    key = load_key(cipherkeyset)
    if EncryptorDecrypt == "E":
        DES_ENCRYPTION(file, key)
    elif EncryptorDecrypt == "D":
        DES_DECRYPTION(file, key)
    else:
        print("IF/ELSE Error in DES.py: des_cipher")
        exit()

