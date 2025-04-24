import streamlit as st
import hashlib
import base64
import json
import os
import time
from cryptography.fernet import Fernet

# ---------------------- Constants & Setup ----------------------
KEY = Fernet.generate_key()
cipher = Fernet(KEY)
DATA_FILE = "data_store.json"
LOCKOUT_DURATION = 60  # seconds

# ---------------------- Helper Functions ----------------------

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)

def hash_passkey_pbkdf2(passkey, salt=None):
    if not salt:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), salt, 100000)
    return base64.b64encode(salt + key).decode()

def verify_passkey_pbkdf2(stored_hash, input_passkey):
    decoded = base64.b64decode(stored_hash.encode())
    salt, original_key = decoded[:16], decoded[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", input_passkey.encode(), salt, 100000)
    return original_key == new_key

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ---------------------- Streamlit Session Setup ----------------------
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "user" not in st.session_state:
    st.session_state.user = None

# ---------------------- User Auth System ----------------------
USERS = {
    "dania": hash_passkey_pbkdf2("mypassword"),
    "admin": hash_passkey_pbkdf2("admin123")
}

def login_ui():
    st.subheader("🔐 Login Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in USERS and verify_passkey_pbkdf2(USERS[username], password):
            st.session_state.user = username
            st.success(f"✅ Welcome {username}!")
            st.rerun()  # 🔁 Fixed here
        else:
            st.error("❌ Invalid credentials")

# ---------------------- Main App ----------------------
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
choice = st.sidebar.selectbox("Navigation", menu)

# Check Lockout
if time.time() < st.session_state.lockout_time:
    remaining = int(st.session_state.lockout_time - time.time())
    st.warning(f"🔒 Locked out! Try again in {remaining} seconds.")
    st.stop()

# Require login
if not st.session_state.user and choice != "Home":
    login_ui()
    st.stop()

# Load user-specific data
stored_data = load_data()
user_data = stored_data.get(st.session_state.user, {}) if st.session_state.user else {}

if choice == "Home":
    st.subheader("🏠 Welcome to Secure Data System")
    st.write("Use this app to securely store and retrieve your data using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_text = st.text_area("Enter your data:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_text and passkey:
            encrypted_text = encrypt_data(user_text)
            hashed_pass = hash_passkey_pbkdf2(passkey)
            user_data[encrypted_text] = {"encrypted_text": encrypted_text, "passkey": hashed_pass}
            stored_data[st.session_state.user] = user_data
            save_data(stored_data)
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_input = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            entry = user_data.get(encrypted_input)
            if entry and verify_passkey_pbkdf2(entry["passkey"], passkey):
                st.session_state.failed_attempts = 0
                decrypted_text = decrypt_data(encrypted_input)
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.warning("🔒 Too many failed attempts! Temporarily locked out.")
                    st.stop()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Logout":
    st.session_state.user = None
    st.session_state.failed_attempts = 0
    st.success("✅ Logged out!")
    st.rerun()  # 🔁 Fixed here too
