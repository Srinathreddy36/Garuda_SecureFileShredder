import os
import time
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_log(log_message: str, password: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(log_message.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return base64.b64encode(salt + iv + encrypted_data)

def decrypt_log(file_path: str, password: str) -> str:
    with open(file_path, "rb") as f:
        data = base64.b64decode(f.read())
        salt, iv, ciphertext = data[:16], data[16:32], data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = sym_padding.PKCS7(128).unpadder()
        return (unpadder.update(padded_data) + unpadder.finalize()).decode()

def secure_delete(file_path: str):
    try:
        size = os.path.getsize(file_path)
        with open(file_path, "r+b") as f:
            for _ in range(3):
                f.seek(0)
                f.write(os.urandom(size))
        os.remove(file_path)
        print("✅ File securely deleted.")

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        log = f"File '{file_path}' was securely deleted at {timestamp}"
        password = getpass("🔐 Set a password to encrypt the deletion log: ")
        encrypted_log = encrypt_log(log, password)

        with open("deletion_log.secure", "wb") as log_file:
            log_file.write(encrypted_log)
        print("📁 Encrypted log saved as 'deletion_log.secure'")

    except Exception as e:
        print(f"❌ Error: {e}")

def view_log():
    try:
        password = getpass("🔑 Enter password to decrypt the log: ")
        log = decrypt_log("deletion_log.secure", password)
        print("\n📜 Deletion Log:\n" + log)
    except Exception as e:
        print(f"❌ Error while decrypting log: {e}")

def main():
    print("\n🚀 Secure File Deleter")
    print("1️⃣  Securely delete a file")
    print("2️⃣  View encrypted deletion log")
    choice = input("➡️  Choose (1 or 2): ")

    if choice == '1':
        file_path = input("📂 Enter file path to delete: ")
        secure_delete(file_path)
    elif choice == '2':
        view_log()
    else:
        print("❌ Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
