# 🛡️ Garuda Secure File Shredder

Garuda Secure File Shredder is an **offline secure file deletion tool** built under the **Garuda Sentinel** cybersecurity mission. It performs **cryptographically secure file wiping**, generates an encrypted log with a **timestamp**, and allows you to view it securely.

## 🔐 Features

- Overwrites file contents with random bytes (3 passes using `os.urandom`)
- Deletes the file from disk
- Logs the deletion activity with a timestamp
- Encrypts the log using AES-CBC with a password-derived key
- Allows viewing the log after decryption with the correct password

## 🚀 How It Works

### 🧹 File Deletion
- You select a file to delete.
- The script overwrites the file contents with random data multiple times.
- The file is then deleted from disk.
- A log entry is created and encrypted with your password.

### 🔐 Log Encryption
- A unique AES-256 key is derived from your password using PBKDF2-HMAC-SHA256.
- The log is padded (PKCS7), encrypted in CBC mode, and stored as `deletion_log.secure`.

### 🔎 Log Viewer
- You can decrypt and read the log by entering the password you used to encrypt it.

## 📦 Requirements

- Python 3.6+
- [cryptography](https://pypi.org/project/cryptography/)
📂 Enter file path to delete: secrets.txt
🔐 Set a password to encrypt the deletion log: ********
✅ File securely deleted.
📁 Encrypted log saved as 'deletion_log.secure'
🔑 Enter password to decrypt the log: ********
📜 Deletion Log:
File 'secrets.txt' was securely deleted at 2025-04-12 08:43:12


```bash
pip install cryptography
🧪 How to Use
python secure_file_deleter.py

