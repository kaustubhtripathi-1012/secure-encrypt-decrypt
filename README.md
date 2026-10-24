# Secure Shield - Message Encryption & Decryption Platform

A military-grade, authenticated message encryption and decryption suite featuring AES-256-GCM symmetric encryption, PBKDF2-HMAC-SHA256 key derivation, persistent SQLite message storage, and cross-platform support across **Web / Desktop** and **Android (APK)**.

---

## 📱 Android APK Package

The Android application has been compiled into a standalone APK:
- **APK File**: `SecureShield-v1.0.apk` (located in the project root)
- **Application Package**: `com.example.secureshield`
- **Architecture**: Native Android (Kotlin + Hardware-Accelerated AES-GCM + Android SQLite + Modern WebView UI)
- **Operation Mode**: 100% Standalone & Offline (Zero external server required)

### How to Install on Android
1. **Via One-Click Script (USB Debugging / Emulator)**:
   - Connect your Android device via USB with USB Debugging enabled (or start an emulator).
   - Double-click or run:
     ```cmd
     .\install_apk.bat
     ```
2. **Via Direct File Transfer**:
   - Send `SecureShield-v1.0.apk` to your phone via USB cable, Google Drive, WhatsApp, or Bluetooth.
   - Tap the APK on your phone and select **Install** (allow *Install from unknown sources* if prompted).

### How to Rebuild the APK
Whenever you make changes to the Android code or assets:
```cmd
.\build_apk.bat
```

---

## 💻 Web / Desktop Application

To launch the web platform locally on your computer:
```cmd
.\run.bat
```
This automatically initializes the virtual environment, verifies dependencies, starts the Flask server at `http://127.0.0.1:5000`, and opens your default browser.

---

## 🔒 Cryptographic Architecture

### 1. Key Derivation (PBKDF2-HMAC-SHA256)
- **Algorithm**: `PBKDF2WithHmacSHA256`
- **Rounds**: `100,000` iterations
- **Key Output**: 256 bits (32 bytes)
- **Salt**: 16 bytes cryptographically secure random bytes (`SecureRandom` / `os.urandom`)
- **Key Formula**: Derives AES key from `password + secret_key` combined with the 16-byte salt.

### 2. Authenticated Encryption (AES-256-GCM)
- **Mode**: Galois/Counter Mode (GCM)
- **Nonce / IV**: 12 random bytes per encryption operation
- **Authentication Tag**: 16 bytes (128-bit) GMAC tag ensuring message integrity and tamper-proofing
- **Combined Payload**: `Base64(Salt [16B] + Nonce [12B] + Ciphertext)` + separate `Base64(Tag [16B])`
- **Cross-Platform Parity**: Messages encrypted on Android can be decrypted on the web server, and vice versa.

### 3. Database Storage
- **Engine**: SQLite 3
- **Tables**:
  - `users`: User account credentials (password protected with PBKDF2 / hashed credentials)
  - `messages`: Saved encrypted records (`title`, `ciphertext`, `nonce`, `tag`, `salt`, `created_at`)

---

## 📁 Project Structure

```
Secure Encrypt and Decrypt/
├── SecureShield-v1.0.apk      # Compiled Android APK ready to install
├── run.bat                    # Launch Desktop / Web platform
├── build_apk.bat              # Rebuild Android APK with Gradle
├── install_apk.bat            # Install APK to device via ADB
├── app.py                     # Flask Web Application Server
├── crypto_helper.py           # Python AES-256-GCM & PBKDF2 helper
├── db_helper.py               # SQLite database manager
├── requirements.txt           # Python dependencies
├── static/                    # Web stylesheets and JavaScript
├── templates/                 # Jinja2 HTML templates
└── android/                   # Full Android Studio project source
    ├── app/
    │   ├── src/main/
    │   │   ├── AndroidManifest.xml
    │   │   ├── java/com/example/secureshield/
    │   │   │   ├── MainActivity.kt         # Android WebView Activity
    │   │   │   ├── bridge/AndroidBridge.kt # JavaScript-to-Kotlin bridge
    │   │   │   ├── crypto/CryptoEngine.kt  # Android AES-256-GCM engine
    │   │   │   └── db/DatabaseHelper.kt    # Android SQLite storage
    │   │   └── assets/                     # Embedded offline Web UI
    │   └── build.gradle.kts
    └── build.gradle.kts
```

---

## 🛡️ Key Features
- **User Authentication**: Secure multi-user login and account creation.
- **Direct Encryption & Storage**: Encrypt messages and save them directly into the encrypted database.
- **Quick Key Generation**: Built-in 128-bit cryptographic random hexadecimal key generator.
- **Raw Decryption**: Decrypt external ciphertext and authentication tags with instant tamper-verification.
- **Saved Messages Management**: Browse saved encrypted messages, decrypt on demand with password/key verification, or delete permanently.
- **Responsive Dark Theme**: Modern glassmorphic dark mode UI designed for phones and desktops.
