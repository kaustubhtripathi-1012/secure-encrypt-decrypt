# Encrypt-Decrypt Application

A secure file encryption and decryption tool built with Python and PyQt6.

## Features
- **Hybrid Encryption**: Uses AES-256-GCM for symmetric encryption and RSA-OAEP for asymmetric encryption.
- **Secure Key Management**: Supports both manually entered keys and automatically generated keys with secure random generation.
- **Password Security**: Protects the private key with a strong password using PBKDF2.
- **Authentication**: Validates file integrity using Authentication Tags.
- **User-Friendly Interface**: Built with PyQt6 for an intuitive GUI experience.

## Prerequisites
- Python 3.x
- PyQt6
- Cryptography

## Installation

1. Clone the repository (if applicable) or download the source code.
2. Install the required dependencies:
   ```bash
   pip install PyQt6 cryptography
   ```

## Usage

1. Run the application:
   ```bash
   .\run.bat
   ```

2. How it Works

2.1 Encryption
1. **Generate Session Key**: A random 256-bit AES key is generated.
2. **Encrypt File**: The content of the file is encrypted using AES-256-GCM with the session key.
3. **Encrypt Session Key**: The AES session key is encrypted using the public key (RSA).
4. **Package Output**: The encrypted file combines:
   -RSA-encrypted AES key
   -Nonce
   -Ciphertext
   -Authentication Tag

2.2 Decryption
1. **Retrieve Session Key**: The RSA-encrypted AES key is decrypted using the private key.
2. **Verify and Decrypt**: The file content is decrypted using AES-256-GCM, and the Authentication Tag is verified to ensure integrity.
