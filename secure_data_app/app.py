import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data store
stored_data = {}
failed_attempts = 0

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt user data
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt user data (check passkey)
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for value in stored_data.values():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

st.set_page_config(page_title="Secure Data App")
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📌 Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve your secret data**.")

elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter Your Secret Data:")
    passkey = st.text_input("Set a Passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data Stored Successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Data")
    encrypted_text = st.text_area("Paste Encrypted Text:")
    passkey = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted = decrypt_data(encrypted_text, passkey)
            if decrypted:
                st.success(f"✅ Your Decrypted Data:\n\n{decrypted}")
            else:
                st.error(f"❌ Wrong passkey! Attempts left: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔐 Too many failed attempts! Redirecting to Login.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ Please fill in all fields.")

elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Change this in real project
            failed_attempts = 0
            st.success("✅ Reauthorized! Go to Retrieve Data.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect master password.")


