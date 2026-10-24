package com.example.secureshield.db

import android.content.ContentValues
import android.content.Context
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.util.Base64
import java.security.SecureRandom
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

data class User(
    val id: Long,
    val username: String
)

data class MessageSummary(
    val id: Long,
    val title: String,
    val createdAt: String
)

data class MessageRecord(
    val id: Long,
    val userId: Long,
    val title: String,
    val ciphertext: String,
    val nonce: String,
    val tag: String,
    val salt: String,
    val createdAt: String
)

class DatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        private const val DATABASE_NAME = "secureshield.db"
        private const val DATABASE_VERSION = 1

        private const val TABLE_USERS = "users"
        private const val COLUMN_USER_ID = "id"
        private const val COLUMN_USERNAME = "username"
        private const val COLUMN_PASSWORD_HASH = "password_hash"

        private const val TABLE_MESSAGES = "messages"
        private const val COLUMN_MSG_ID = "id"
        private const val COLUMN_MSG_USER_ID = "user_id"
        private const val COLUMN_MSG_TITLE = "title"
        private const val COLUMN_MSG_CIPHERTEXT = "ciphertext"
        private const val COLUMN_MSG_NONCE = "nonce"
        private const val COLUMN_MSG_TAG = "tag"
        private const val COLUMN_MSG_SALT = "salt"
        private const val COLUMN_MSG_CREATED_AT = "created_at"
    }

    private val secureRandom = SecureRandom()

    override fun onCreate(db: SQLiteDatabase) {
        val createUsersTable = """
            CREATE TABLE $TABLE_USERS (
                $COLUMN_USER_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COLUMN_USERNAME TEXT UNIQUE NOT NULL,
                $COLUMN_PASSWORD_HASH TEXT NOT NULL
            )
        """.trimIndent()

        val createMessagesTable = """
            CREATE TABLE $TABLE_MESSAGES (
                $COLUMN_MSG_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COLUMN_MSG_USER_ID INTEGER NOT NULL,
                $COLUMN_MSG_TITLE TEXT NOT NULL,
                $COLUMN_MSG_CIPHERTEXT TEXT NOT NULL,
                $COLUMN_MSG_NONCE TEXT NOT NULL,
                $COLUMN_MSG_TAG TEXT NOT NULL,
                $COLUMN_MSG_SALT TEXT NOT NULL,
                $COLUMN_MSG_CREATED_AT TEXT NOT NULL,
                FOREIGN KEY ($COLUMN_MSG_USER_ID) REFERENCES $TABLE_USERS($COLUMN_USER_ID) ON DELETE CASCADE
            )
        """.trimIndent()

        db.execSQL(createUsersTable)
        db.execSQL(createMessagesTable)
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_MESSAGES")
        db.execSQL("DROP TABLE IF EXISTS $TABLE_USERS")
        onCreate(db)
    }

    private fun hashPassword(password: String, salt: ByteArray): String {
        val spec = PBEKeySpec(password.toCharArray(), salt, 20_000, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hash = factory.generateSecret(spec).encoded
        val saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP)
        val hashB64 = Base64.encodeToString(hash, Base64.NO_WRAP)
        return "$saltB64:$hashB64"
    }

    private fun verifyPassword(password: String, storedHash: String): Boolean {
        return try {
            val parts = storedHash.split(":")
            if (parts.size != 2) return false
            val salt = Base64.decode(parts[0], Base64.DEFAULT)
            val expectedHash = parts[1]
            val spec = PBEKeySpec(password.toCharArray(), salt, 20_000, 256)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val computedHash = Base64.encodeToString(factory.generateSecret(spec).encoded, Base64.NO_WRAP)
            computedHash == expectedHash
        } catch (e: Exception) {
            false
        }
    }

    fun createUser(username: String, password: String): Boolean {
        val trimmed = username.trim()
        if (trimmed.isEmpty() || password.length < 6) return false

        val salt = ByteArray(16)
        secureRandom.nextBytes(salt)
        val passwordHash = hashPassword(password, salt)

        val db = writableDatabase
        val values = ContentValues().apply {
            put(COLUMN_USERNAME, trimmed)
            put(COLUMN_PASSWORD_HASH, passwordHash)
        }

        return try {
            val result = db.insertOrThrow(TABLE_USERS, null, values)
            result != -1L
        } catch (e: Exception) {
            false
        }
    }

    fun verifyUser(username: String, password: String): User? {
        val trimmed = username.trim()
        val db = readableDatabase
        val cursor = db.query(
            TABLE_USERS,
            arrayOf(COLUMN_USER_ID, COLUMN_USERNAME, COLUMN_PASSWORD_HASH),
            "$COLUMN_USERNAME = ?",
            arrayOf(trimmed),
            null, null, null
        )

        cursor.use {
            if (it.moveToFirst()) {
                val id = it.getLong(it.getColumnIndexOrThrow(COLUMN_USER_ID))
                val user = it.getString(it.getColumnIndexOrThrow(COLUMN_USERNAME))
                val hash = it.getString(it.getColumnIndexOrThrow(COLUMN_PASSWORD_HASH))
                if (verifyPassword(password, hash)) {
                    return User(id, user)
                }
            }
        }
        return null
    }

    fun saveMessage(
        userId: Long,
        title: String,
        ciphertext: String,
        nonce: String,
        tag: String,
        salt: String
    ): Boolean {
        val db = writableDatabase
        val sdf = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
        val now = sdf.format(Date())

        val values = ContentValues().apply {
            put(COLUMN_MSG_USER_ID, userId)
            put(COLUMN_MSG_TITLE, title.trim())
            put(COLUMN_MSG_CIPHERTEXT, ciphertext)
            put(COLUMN_MSG_NONCE, nonce)
            put(COLUMN_MSG_TAG, tag)
            put(COLUMN_MSG_SALT, salt)
            put(COLUMN_MSG_CREATED_AT, now)
        }

        return try {
            val rowId = db.insert(TABLE_MESSAGES, null, values)
            rowId != -1L
        } catch (e: Exception) {
            false
        }
    }

    fun getUserMessages(userId: Long): List<MessageSummary> {
        val db = readableDatabase
        val list = mutableListOf<MessageSummary>()
        val cursor = db.query(
            TABLE_MESSAGES,
            arrayOf(COLUMN_MSG_ID, COLUMN_MSG_TITLE, COLUMN_MSG_CREATED_AT),
            "$COLUMN_MSG_USER_ID = ?",
            arrayOf(userId.toString()),
            null, null,
            "$COLUMN_MSG_ID DESC"
        )

        cursor.use {
            while (it.moveToNext()) {
                val id = it.getLong(it.getColumnIndexOrThrow(COLUMN_MSG_ID))
                val title = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_TITLE))
                val date = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_CREATED_AT))
                list.add(MessageSummary(id, title, date))
            }
        }
        return list
    }

    fun getMessage(msgId: Long, userId: Long): MessageRecord? {
        val db = readableDatabase
        val cursor = db.query(
            TABLE_MESSAGES,
            arrayOf(
                COLUMN_MSG_ID,
                COLUMN_MSG_USER_ID,
                COLUMN_MSG_TITLE,
                COLUMN_MSG_CIPHERTEXT,
                COLUMN_MSG_NONCE,
                COLUMN_MSG_TAG,
                COLUMN_MSG_SALT,
                COLUMN_MSG_CREATED_AT
            ),
            "$COLUMN_MSG_ID = ? AND $COLUMN_MSG_USER_ID = ?",
            arrayOf(msgId.toString(), userId.toString()),
            null, null, null
        )

        cursor.use {
            if (it.moveToFirst()) {
                return MessageRecord(
                    id = it.getLong(it.getColumnIndexOrThrow(COLUMN_MSG_ID)),
                    userId = it.getLong(it.getColumnIndexOrThrow(COLUMN_MSG_USER_ID)),
                    title = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_TITLE)),
                    ciphertext = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_CIPHERTEXT)),
                    nonce = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_NONCE)),
                    tag = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_TAG)),
                    salt = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_SALT)),
                    createdAt = it.getString(it.getColumnIndexOrThrow(COLUMN_MSG_CREATED_AT))
                )
            }
        }
        return null
    }

    fun deleteMessage(msgId: Long, userId: Long): Boolean {
        val db = writableDatabase
        val count = db.delete(
            TABLE_MESSAGES,
            "$COLUMN_MSG_ID = ? AND $COLUMN_MSG_USER_ID = ?",
            arrayOf(msgId.toString(), userId.toString())
        )
        return count > 0
    }
}
