import streamlit as st
from PIL import Image
import io
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --- PAGE CONFIG ---
st.set_page_config(page_title="Project KAVACH", page_icon="🛡️", layout="centered")

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    .stApp {background-color: #0e1117; color: #00ff00;}
    .stTextInput>div>div>input {color: #00ff00; background-color: #262730;}
    .stButton>button {border: 1px solid #00ff00; color: #00ff00; background-color: transparent;}
    h1, h2, h3 {font-family: 'Courier New', monospace; color: #00ff00;}
    </style>
""", unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---
def derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(password.encode())

def encrypt_message(message, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(message.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted_data).decode('utf-8')

def decrypt_message(encrypted_package, password):
    try:
        data = base64.b64decode(encrypted_package)
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        key = derive_key(password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except:
        raise ValueError("Decryption failed")

def encode_image(image, secret_data):
    binary_data = ''.join(format(ord(i), '08b') for i in secret_data) + ''.join(format(ord(i), '08b') for i in "#####")
    data_index = 0
    img_data = image.getdata()
    new_img_data = []
    for pixel in img_data:
        if data_index < len(binary_data):
            r, g, b = pixel[0], pixel[1], pixel[2]
            new_r = (r & ~1) | int(binary_data[data_index])
            new_img_data.append((new_r, g, b))
            data_index += 1
        else:
            new_img_data.append(pixel)
    new_img = Image.new(image.mode, image.size)
    new_img.putdata(new_img_data)
    return new_img

def decode_image(image):
    img_data = image.getdata()
    binary_data = ""
    for pixel in img_data:
        binary_data += str(pixel[0] & 1)
    all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
    decoded_data = ""
    for byte in all_bytes:
        decoded_data += chr(int(byte, 2))
        if decoded_data.endswith("#####"):
            return decoded_data[:-5]
    return ""

# --- MAIN UI ---
st.title("🛡️ PROJECT KAVACH")
tab1, tab2 = st.tabs(["🔒 ENCRYPT", "🔓 DECRYPT"])

with tab1:
    st.write("### Hide Data")
    uploaded_file = st.file_uploader("Upload Image", type=["png", "jpg"])
    secret_text = st.text_area("Secret Message")
    password = st.text_input("Password", type="password")
    if st.button("ENCRYPT"):
        if uploaded_file and secret_text and password:
            enc_str = encrypt_message(secret_text, password)
            orig_img = Image.open(uploaded_file).convert("RGB")
            stego_img = encode_image(orig_img, enc_str)
            buf = io.BytesIO()
            stego_img.save(buf, format="PNG")
            st.download_button("DOWNLOAD IMAGE", data=buf.getvalue(), file_name="secure.png", mime="image/png")
            st.success("Hidden Successfully!")

with tab2:
    st.write("### Extract Data")
    dec_file = st.file_uploader("Upload Stego Image", type=["png"])
    dec_pass = st.text_input("Password", type="password", key="d")
    if st.button("DECRYPT"):
        if dec_file and dec_pass:
            try:
                stego_img = Image.open(dec_file).convert("RGB")
                hidden = decode_image(stego_img)
                if hidden:
                    dec_text = decrypt_message(hidden, dec_pass)
                    st.success(f"MESSAGE: {dec_text.decode('utf-8')}")
                else:
                    st.warning("No message found.")
            except:
                st.error("Access Denied.")
