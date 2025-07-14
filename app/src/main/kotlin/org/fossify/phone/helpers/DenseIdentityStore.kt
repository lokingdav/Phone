package org.fossify.phone.helpers

import android.content.Context
import android.content.SharedPreferences
import android.util.Log

/**
 * A simple key–value store backed by SharedPreferences.
 * Call [init] once (e.g. in Application.onCreate), then use the getters/setters anywhere.
 */
object DenseIdentityStore {
    private const val PREFS_NAME = "dense_identity_prefs"
    private lateinit var prefs: SharedPreferences

    /** Must be called before any other method */
    fun init(context: Context) {
        Log.d("DenseIdentityStore", "init DenseIdentityStore")
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    // String
    fun putString(key: String, value: String) =
        prefs.edit().putString(key, value).apply()

    fun getString(key: String, default: String? = null): String? =
        prefs.getString(key, default)

    // Boolean
    fun putBoolean(key: String, value: Boolean) =
        prefs.edit().putBoolean(key, value).apply()

    fun getBoolean(key: String, default: Boolean = false): Boolean =
        prefs.getBoolean(key, default)

    // Int
    fun putInt(key: String, value: Int) =
        prefs.edit().putInt(key, value).apply()

    fun getInt(key: String, default: Int = 0): Int =
        prefs.getInt(key, default)

    // Long
    fun putLong(key: String, value: Long) =
        prefs.edit().putLong(key, value).apply()

    fun getLong(key: String, default: Long = 0L): Long =
        prefs.getLong(key, default)

    // Float
    fun putFloat(key: String, value: Float) =
        prefs.edit().putFloat(key, value).apply()

    fun getFloat(key: String, default: Float = 0f): Float =
        prefs.getFloat(key, default)

    // Remove a single key
    fun remove(key: String) =
        prefs.edit().remove(key).apply()

    // Clear everything
    fun clearAll() =
        prefs.edit().clear().apply()
}
