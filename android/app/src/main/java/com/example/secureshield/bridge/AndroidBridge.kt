package com.example.secureshield.bridge

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.webkit.JavascriptInterface
import android.widget.Toast
import com.example.secureshield.crypto.CryptoEngine
import com.example.secureshield.db.DatabaseHelper
import com.example.secureshield.db.User
import org.json.JSONArray
import org.json.JSONObject

class AndroidBridge(
    private val context: Context,
    private val onLogoutCallback: () -> Unit = {}
) {
    private val dbHelper = DatabaseHelper(context)
    private var currentUser: User? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    @JavascriptInterface
    fun login(username: String, password: String): String {
        val user = dbHelper.verifyUser(username, password)
        val json = JSONObject()
        if (user != null) {
            currentUser = user
            json.put("success", true)
            val userObj = JSONObject()
            userObj.put("id", user.id)
            userObj.put("username", user.username)
            json.put("user", userObj)
        } else {
            json.put("success", false)
            json.put("error", "Invalid username or password.")
        }
        return json.toString()
    }

    @JavascriptInterface
    fun register(username: String, password: String, confirmPassword: String): String {
        val json = JSONObject()
        if (username.isBlank() || password.isBlank() || confirmPassword.isBlank()) {
            json.put("success", false)
            json.put("error", "All fields are required.")
            return json.toString()
        }
        if (password != confirmPassword) {
            json.put("success", false)
            json.put("error", "Passwords do not match.")
            return json.toString()
        }
        if (password.length < 6) {
            json.put("success", false)
            json.put("error", "Password must be at least 6 characters long.")
            return json.toString()
        }

        val success = dbHelper.createUser(username, password)
        if (success) {
            json.put("success", true)
            json.put("message", "Account created successfully! Please log in.")
        } else {
            json.put("success", false)
            json.put("error", "Username is already taken.")
        }
        return json.toString()
    }

    @JavascriptInterface
    fun logout(): String {
        currentUser = null
        onLogoutCallback()
        val json = JSONObject()
        json.put("success", true)
        return json.toString()
    }

    @JavascriptInterface
    fun getCurrentUser(): String {
        val json = JSONObject()
        if (currentUser != null) {
            json.put("loggedIn", true)
            val u = JSONObject()
            u.put("id", currentUser!!.id)
            u.put("username", currentUser!!.username)
            json.put("user", u)
        } else {
            json.put("loggedIn", false)
        }
        return json.toString()
    }

    @JavascriptInterface
    fun encryptMessage(title: String, message: String, password: String, secretKey: String): String {
        val json = JSONObject()
        val user = currentUser
        if (user == null) {
            json.put("success", false)
            json.put("error", "Unauthorized. Please log in.")
            return json.toString()
        }

        if (title.isBlank() || message.isBlank() || password.isBlank() || secretKey.isBlank()) {
            json.put("success", false)
            json.put("error", "All fields (title, message, password, secret key) are required.")
            return json.toString()
        }

        try {
            val enc = CryptoEngine.encrypt(message, password, secretKey)
            val saved = dbHelper.saveMessage(
                userId = user.id,
                title = title,
                ciphertext = enc.ciphertext,
                nonce = enc.nonce,
                tag = enc.tag,
                salt = enc.salt
            )

            if (saved) {
                json.put("success", true)
                json.put("message", "Message encrypted and stored safely in Android SQLite database.")
                val cryptoData = JSONObject()
                cryptoData.put("ciphertext", enc.combinedCiphertext)
                cryptoData.put("tag", enc.tag)
                json.put("crypto_data", cryptoData)
            } else {
                json.put("success", false)
                json.put("error", "Failed to save message to local SQLite database.")
            }
        } catch (e: Exception) {
            json.put("success", false)
            json.put("error", "Encryption error: ${e.message}")
        }
        return json.toString()
    }

    @JavascriptInterface
    fun decryptRaw(ciphertextB64: String, tagB64: String, password: String, secretKey: String): String {
        val json = JSONObject()
        if (ciphertextB64.isBlank() || tagB64.isBlank() || password.isBlank() || secretKey.isBlank()) {
            json.put("success", false)
            json.put("error", "Ciphertext, Auth Tag, Password, and Secret Key are required.")
            return json.toString()
        }

        val decrypted = CryptoEngine.decrypt(
            ciphertextB64 = ciphertextB64,
            nonceB64 = null,
            tagB64 = tagB64,
            saltB64 = null,
            password = password,
            secretKey = secretKey
        )

        if (decrypted != null) {
            json.put("success", true)
            json.put("decrypted", decrypted)
        } else {
            json.put("success", false)
            json.put("error", "Authentication failed. Incorrect Password or Secret Key.")
        }
        return json.toString()
    }

    @JavascriptInterface
    fun getMessages(): String {
        val json = JSONObject()
        val user = currentUser
        if (user == null) {
            json.put("success", false)
            json.put("error", "Unauthorized.")
            return json.toString()
        }

        val list = dbHelper.getUserMessages(user.id)
        val arr = JSONArray()
        for (item in list) {
            val obj = JSONObject()
            obj.put("id", item.id)
            obj.put("title", item.title)
            obj.put("created_at", item.createdAt)
            arr.put(obj)
        }
        json.put("success", true)
        json.put("messages", arr)
        return json.toString()
    }

    @JavascriptInterface
    fun decryptSavedMessage(msgId: Long, password: String, secretKey: String): String {
        val json = JSONObject()
        val user = currentUser
        if (user == null) {
            json.put("success", false)
            json.put("error", "Unauthorized.")
            return json.toString()
        }

        val record = dbHelper.getMessage(msgId, user.id)
        if (record == null) {
            json.put("success", false)
            json.put("error", "Message not found or access denied.")
            return json.toString()
        }

        val decrypted = CryptoEngine.decrypt(
            ciphertextB64 = record.ciphertext,
            nonceB64 = record.nonce,
            tagB64 = record.tag,
            saltB64 = record.salt,
            password = password,
            secretKey = secretKey
        )

        if (decrypted != null) {
            json.put("success", true)
            json.put("decrypted", decrypted)
        } else {
            json.put("success", false)
            json.put("error", "Authentication failed. Incorrect Password or Secret Key.")
        }
        return json.toString()
    }

    @JavascriptInterface
    fun deleteMessage(msgId: Long): String {
        val json = JSONObject()
        val user = currentUser
        if (user == null) {
            json.put("success", false)
            json.put("error", "Unauthorized.")
            return json.toString()
        }

        val success = dbHelper.deleteMessage(msgId, user.id)
        json.put("success", success)
        if (success) {
            json.put("message", "Message deleted successfully.")
        } else {
            json.put("error", "Failed to delete message.")
        }
        return json.toString()
    }

    @JavascriptInterface
    fun generateSecretKey(): String {
        return CryptoEngine.generateRandomHexKey()
    }

    @JavascriptInterface
    fun copyToClipboard(text: String, label: String) {
        mainHandler.post {
            try {
                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText(label, text)
                clipboard.setPrimaryClip(clip)
                Toast.makeText(context, "$label copied to clipboard", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                // ignore
            }
        }
    }

    @JavascriptInterface
    fun showToast(message: String) {
        mainHandler.post {
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        }
    }

    @JavascriptInterface
    fun getPlatformInfo(): String {
        val json = JSONObject()
        json.put("platform", "Android Standalone Native APK")
        json.put("osVersion", android.os.Build.VERSION.RELEASE)
        json.put("deviceModel", "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}")
        json.put("storage", "SQLite 3 Local DB")
        json.put("cipher", "AES-256-GCM")
        json.put("kdf", "PBKDF2-HMAC-SHA256 (100,000 iterations)")
        return json.toString()
    }
}
