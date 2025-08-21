package org.fossify.phone.callerauth

import android.content.Context
import android.content.SharedPreferences
import android.util.Log

private const val TAG = "CallAuth"
object Storage {
    private const val PREFS_NAME = "dense_identity_prefs"
    private lateinit var prefs: SharedPreferences


    fun init(context: Context) {
        Log.d(TAG, "init Store")
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    // String
    fun putString(key: String, value: String?) =
        prefs.edit().putString(key, value).apply()

    fun getString(key: String, default: String? = null): String? =
        prefs.getString(key, default)

    // Clear everything
    fun clearAll() =
        prefs.edit().clear().apply()
}
