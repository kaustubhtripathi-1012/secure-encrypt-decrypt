package com.example.secureshield.crypto

import android.util.Base64
import java.nio.ByteBuffer
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedResult(
    val ciphertext: String,
    val nonce: String,
    val tag: String,
    val salt: String,
    val combinedCiphertext: String
)

object CryptoEngine {
    private const val ITERATIONS = 100_000
    private const val KEY_LENGTH_BITS = 256
    private const val SALT_LENGTH_BYTES = 16
    private const val NONCE_LENGTH_BYTES = 12
    private const val TAG_LENGTH_BITS = 128
    private const val TAG_LENGTH_BYTES = 16

    private val secureRandom = SecureRandom()

    /**
     * Derives a 256-bit AES key from (password + secretKey) and salt using PBKDF2WithHmacSHA256.
     * Matches Python's PBKDF2HMAC(SHA256, length=32, salt=salt, iterations=100000).
     */
    fun deriveKey(password: String, secretKey: String, salt: ByteArray): SecretKey {
        val combined = "$password$secretKey"
        val spec = PBEKeySpec(combined.toCharArray(), salt, ITERATIONS, KEY_LENGTH_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = factory.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }

    /**
     * Encrypts a plaintext message using AES-256-GCM.
     * Returns Base64 strings matching Python's output format.
     */
    fun encrypt(message: String, password: String, secretKey: String): EncryptedResult {
        val salt = ByteArray(SALT_LENGTH_BYTES)
        secureRandom.nextBytes(salt)

        val nonce = ByteArray(NONCE_LENGTH_BYTES)
        secureRandom.nextBytes(nonce)

        val key = deriveKey(password, secretKey, salt)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec)

        val encryptedWithTag = cipher.doFinal(message.toByteArray(Charsets.UTF_8))
        val ciphertextLength = encryptedWithTag.size - TAG_LENGTH_BYTES
        val ciphertext = encryptedWithTag.copyOfRange(0, ciphertextLength)
        val tag = encryptedWithTag.copyOfRange(ciphertextLength, encryptedWithTag.size)

        // Combined payload: salt (16 bytes) + nonce (12 bytes) + ciphertext
        val combinedBuf = ByteBuffer.allocate(salt.size + nonce.size + ciphertext.size)
        combinedBuf.put(salt)
        combinedBuf.put(nonce)
        combinedBuf.put(ciphertext)
        val combinedBytes = combinedBuf.array()

        return EncryptedResult(
            ciphertext = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
            nonce = Base64.encodeToString(nonce, Base64.NO_WRAP),
            tag = Base64.encodeToString(tag, Base64.NO_WRAP),
            salt = Base64.encodeToString(salt, Base64.NO_WRAP),
            combinedCiphertext = Base64.encodeToString(combinedBytes, Base64.NO_WRAP)
        )
    }

    /**
     * Decrypts an AES-256-GCM payload.
     * Supports both combined format (salt + nonce + ciphertext) or separate parameters.
     * Returns the plaintext string, or null if authentication fails.
     */
    fun decrypt(
        ciphertextB64: String,
        nonceB64: String? = null,
        tagB64: String? = null,
        saltB64: String? = null,
        password: String,
        secretKey: String
    ): String? {
        return try {
            val salt: ByteArray
            val nonce: ByteArray
            val ciphertext: ByteArray

            if (nonceB64.isNullOrEmpty() || saltB64.isNullOrEmpty()) {
                val combined = Base64.decode(ciphertextB64, Base64.DEFAULT)
                if (combined.size < SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES) {
                    return null
                }
                salt = combined.copyOfRange(0, SALT_LENGTH_BYTES)
                nonce = combined.copyOfRange(SALT_LENGTH_BYTES, SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES)
                ciphertext = combined.copyOfRange(SALT_LENGTH_BYTES + NONCE_LENGTH_BYTES, combined.size)
            } else {
                salt = Base64.decode(saltB64, Base64.DEFAULT)
                nonce = Base64.decode(nonceB64, Base64.DEFAULT)
                ciphertext = Base64.decode(ciphertextB64, Base64.DEFAULT)
            }

            if (tagB64.isNullOrEmpty()) {
                return null
            }
            val tag = Base64.decode(tagB64, Base64.DEFAULT)

            val key = deriveKey(password, secretKey, salt)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val gcmSpec = GCMParameterSpec(TAG_LENGTH_BITS, nonce)
            cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec)

            // Java AES/GCM expects ciphertext + tag
            val toDecrypt = ByteBuffer.allocate(ciphertext.size + tag.size)
                .put(ciphertext)
                .put(tag)
                .array()

            val decryptedBytes = cipher.doFinal(toDecrypt)
            String(decryptedBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            // Authentication failed or invalid ciphertext/key
            null
        }
    }

    /**
     * Generates a 128-bit (16-byte) random hexadecimal secret key (32 hex characters).
     */
    fun generateRandomHexKey(): String {
        val bytes = ByteArray(16)
        secureRandom.nextBytes(bytes)
        val sb = StringBuilder()
        for (b in bytes) {
            sb.append(String.format("%02X", b))
        }
        return sb.toString()
    }
}
