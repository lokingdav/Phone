package org.fossify.phone.callerauth

import android.content.Context
import android.content.SharedPreferences
import android.util.Log

private const val TAG = "CallAuth"
object Storage {
    private const val PREFS_NAME = "dense_identity_prefs"
    private const val KEY_DIA_CONFIG = "dia_config_env"
    private const val KEY_ENROLLED_PHONE = "enrolled_phone"
    
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

    // DiaConfig helpers
    /**
     * Saves DiaConfig environment string to persistent storage.
     */
    fun saveDiaConfig(envString: String) {
        Log.d(TAG, "Saving DiaConfig to storage (${envString.length} chars)")
        putString(KEY_DIA_CONFIG, envString)
    }

    /**
     * Loads DiaConfig environment string from persistent storage.
     * @return Environment string or null if not enrolled
     */
    fun loadDiaConfig(): String? {
        return getString(KEY_DIA_CONFIG)
    }

    /**
     * Checks if user has enrolled (has saved DiaConfig).
     */
    fun isEnrolled(): Boolean {
        return loadDiaConfig() != null
    }

    fun saveEnrolledPhone(phoneNumber: String) {
        putString(KEY_ENROLLED_PHONE, phoneNumber)
    }

    fun loadEnrolledPhone(): String? {
        return getString(KEY_ENROLLED_PHONE)
    }

    /**
     * Clears enrollment data.
     */
    fun clearEnrollment() {
        Log.d(TAG, "Clearing enrollment data")
        putString(KEY_DIA_CONFIG, null)
        putString(KEY_ENROLLED_PHONE, null)
    }
}
