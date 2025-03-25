import streamlit as st

st.set_page_config(page_title="Encryption & Decryption Tool", layout="centered")
st.title("Encryption & Decryption Tool")

# --- Cipher Functions ---

def additive_encrypt(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shift = (ord(char.upper()) - 65 + key) % 26
            result += chr(shift + 65) if char.isupper() else chr(shift + 97)
        else:
            result += char
    return result

def additive_decrypt(text, key):
    return additive_encrypt(text, -key)


def multiplicative_encrypt(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shift = ((ord(char.upper()) - 65) * key) % 26
            result += chr(shift + 65) if char.isupper() else chr(shift + 97)
        else:
            result += char
    return result

def multiplicative_decrypt(text, key):
    inv_key = pow(key, -1, 26)
    return multiplicative_encrypt(text, inv_key)


def affine_encrypt(text, a, b):
    result = ''
    for char in text:
        if char.isalpha():
            shift = ((ord(char.upper()) - 65) * a + b) % 26
            result += chr(shift + 65) if char.isupper() else chr(shift + 97)
        else:
            result += char
    return result

def affine_decrypt(text, a, b):
    inv_a = pow(a, -1, 26)
    result = ''
    for char in text:
        if char.isalpha():
            shift = ((ord(char.upper()) - 65 - b) * inv_a) % 26
            result += chr(shift + 65) if char.isupper() else chr(shift + 97)
        else:
            result += char
    return result

# --- New Combined Cipher (Affine + Vigenere + Transposition + Stream XOR) ---

def vigenere_encrypt(text, key):
    key = key.lower()
    key_index = 0
    result = ''
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            shifted = (ord(char.lower()) - 97 + shift) % 26
            result += chr(shifted + 97) if char.islower() else chr(shifted + 65)
            key_index += 1
        else:
            result += char
    return result

def vigenere_decrypt(text, key):
    key = key.lower()
    key_index = 0
    result = ''
    for char in text:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - 97
            shifted = (ord(char.lower()) - 97 - shift + 26) % 26
            result += chr(shifted + 97) if char.islower() else chr(shifted + 65)
            key_index += 1
        else:
            result += char
    return result

def transposition_encrypt(text):
    result = text[::2] + text[1::2]
    return result

def transposition_decrypt(text):
    mid = (len(text) + 1) // 2
    first_half = text[:mid]
    second_half = text[mid:]
    result = ''.join(a + b for a, b in zip(first_half, second_half))
    if len(first_half) > len(second_half):
        result += first_half[-1]
    return result

def stream_xor_encrypt(text, key):
    result = ''
    for i, char in enumerate(text):
        result += chr(ord(char) ^ key[i % len(key)])
    return result

def stream_xor_decrypt(text, key):
    return stream_xor_encrypt(text, key)  # XOR is symmetric

# Final Combined Cipher Functions

def ultimate_cipher_encrypt(text, a, b, vig_key, xor_key):
    step1 = affine_encrypt(text, a, b)
    step2 = vigenere_encrypt(step1, vig_key)
    step3 = transposition_encrypt(step2)
    final = stream_xor_encrypt(step3, xor_key.encode())
    return final

def ultimate_cipher_decrypt(text, a, b, vig_key, xor_key):
    step1 = stream_xor_decrypt(text, xor_key.encode())
    step2 = transposition_decrypt(step1)
    step3 = vigenere_decrypt(step2, vig_key)
    final = affine_decrypt(step3, a, b)
    return final

# Combined Cipher (Additive + Multiplicative)

def combined_encrypt(text, add_key, mult_key):
    step1 = additive_encrypt(text, add_key)
    final = multiplicative_encrypt(step1, mult_key)
    return final

def combined_decrypt(text, add_key, mult_key):
    step1 = multiplicative_decrypt(text, mult_key)
    final = additive_decrypt(step1, add_key)
    return final

# Placeholder functions for other ciphers (implementations can be added similarly)

def dummy_encrypt(text, key=None):
    return f"Encrypted({text})"

def dummy_decrypt(text, key=None):
    return f"Decrypted({text})"

# Sidebar for navigation
cipher_choice = st.sidebar.selectbox("Select Cipher", [
    "Ultimate Cipher (Affine + Vigenere + Transposition + XOR)",
    "Additive Cipher", "Multiplicative Cipher", "Affine Cipher",
    "Combined Cipher (Additive + Multiplicative)",
    "Autokey Cipher", "Playfair Cipher", "Vigenere Cipher",
    "Keyless Transposition Cipher", "Keyed Transposition Cipher",
    "Stream Cipher", "Block Cipher", "RSA Algorithm",
    "Euclidean Algorithm", "Diffie-Hellman Key Exchange"
])

st.subheader(f"You selected: {cipher_choice}")

# Common input fields
text_input = st.text_area("Enter Text (Plaintext or Ciphertext)", height=150)
action = st.radio("Choose Action", ["Encrypt", "Decrypt"])

# Cipher-specific input fields and processing
if cipher_choice == "Ultimate Cipher (Affine + Vigenere + Transposition + XOR)":
    st.info("This cipher combines Affine Cipher, Vigenere Cipher, Transposition Cipher, and XOR-based Stream Cipher.")
    a = st.number_input("Enter Affine Key 'a'", min_value=1, step=1)
    b = st.number_input("Enter Affine Key 'b'", min_value=0, step=1)
    vig_key = st.text_input("Enter Vigenere Key (Alphabetic)")
    xor_key = st.text_input("Enter XOR Key (Text)")
    if st.button("Process"):
        if action == "Encrypt":
            result = ultimate_cipher_encrypt(text_input, a, b, vig_key, xor_key)
        else:
            result = ultimate_cipher_decrypt(text_input, a, b, vig_key, xor_key)
        st.text_area("Result", value=result, height=150)

elif cipher_choice in ["Additive Cipher", "Multiplicative Cipher"]:
    key = st.number_input("Enter Key (Integer)", min_value=1, step=1)
    if st.button("Process"):
        if cipher_choice == "Additive Cipher":
            result = additive_encrypt(text_input, key) if action == "Encrypt" else additive_decrypt(text_input, key)
        else:
            result = multiplicative_encrypt(text_input, key) if action == "Encrypt" else multiplicative_decrypt(text_input, key)
        st.text_area("Result", value=result, height=150)

elif cipher_choice == "Affine Cipher":
    a = st.number_input("Enter 'a' (Multiplicative Key)", min_value=1, step=1)
    b = st.number_input("Enter 'b' (Additive Key)", min_value=0, step=1)
    if st.button("Process"):
        result = affine_encrypt(text_input, a, b) if action == "Encrypt" else affine_decrypt(text_input, a, b)
        st.text_area("Result", value=result, height=150)

elif cipher_choice == "Combined Cipher (Additive + Multiplicative)":
    add_key = st.number_input("Enter Additive Key", min_value=1, step=1)
    mult_key = st.number_input("Enter Multiplicative Key", min_value=1, step=1)
    if st.button("Process"):
        result = combined_encrypt(text_input, add_key, mult_key) if action == "Encrypt" else combined_decrypt(text_input, add_key, mult_key)
        st.text_area("Result", value=result, height=150)

elif cipher_choice in ["Autokey Cipher", "Playfair Cipher", "Vigenere Cipher"]:
    key = st.text_input("Enter Key (Alphabetic)")
    if st.button("Process"):
        result = dummy_encrypt(text_input, key) if action == "Encrypt" else dummy_decrypt(text_input, key)
        st.text_area("Result", value=result, height=150)
