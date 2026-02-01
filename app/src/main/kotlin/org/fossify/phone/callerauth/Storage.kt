package org.fossify.phone.callerauth

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import android.util.Base64
import org.fossify.phone.BuildConfig

private const val TAG = "CallAuth"
object Storage {
    private const val PREFS_NAME = "dense_identity_prefs"
    private const val PEER_SESSIONS_PREFS_NAME = "dense_identity_peer_sessions"

    private const val KEY_DIA_CONFIG = "dia_config_env"
    private const val KEY_ENROLLED_PHONE = "enrolled_phone"

    private const val KEY_PEER_SESSION_CACHE_ENABLED = "peer_session_cache_enabled"
    private const val KEY_AUTO_ODA_ENABLED = "auto_oda_enabled"

    private const val KEY_ES_HOST_OVERRIDE = "es_host_override"
    private const val KEY_ES_PORT_OVERRIDE = "es_port_override"
    private const val KEY_RS_HOST_OVERRIDE = "rs_host_override"
    private const val KEY_RS_PORT_OVERRIDE = "rs_port_override"
    
    private lateinit var prefs: SharedPreferences
    private lateinit var peerSessionPrefs: SharedPreferences

    fun init(context: Context) {
        Log.d(TAG, "init Store")
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        peerSessionPrefs = context.getSharedPreferences(PEER_SESSIONS_PREFS_NAME, Context.MODE_PRIVATE)
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

    // Peer session cache toggle (default OFF)
    fun isPeerSessionCacheEnabled(): Boolean {
        return prefs.getBoolean(KEY_PEER_SESSION_CACHE_ENABLED, false)
    }

    fun setPeerSessionCacheEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_PEER_SESSION_CACHE_ENABLED, enabled).apply()
    }

    // Auto ODA toggle (default OFF)
    fun isAutoOdaEnabled(): Boolean {
        return prefs.getBoolean(KEY_AUTO_ODA_ENABLED, false)
    }

    fun setAutoOdaEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_AUTO_ODA_ENABLED, enabled).apply()
    }

    // Peer session persistence
    private fun normalizePeerKey(peer: String): String = peer.filter { it.isDigit() }

    fun savePeerSession(peer: String, session: ByteArray) {
        val key = normalizePeerKey(peer)
        if (key.isBlank()) {
            return
        }
        val b64 = Base64.encodeToString(session, Base64.NO_WRAP)
        peerSessionPrefs.edit().putString(key, b64).apply()
    }

    fun loadPeerSession(peer: String): ByteArray? {
        val key = normalizePeerKey(peer)
        if (key.isBlank()) {
            return null
        }
        val b64 = peerSessionPrefs.getString(key, null) ?: return null
        return try {
            Base64.decode(b64, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    fun clearAllPeerSessions() {
        peerSessionPrefs.edit().clear().apply()
    }

    fun saveEnrolledPhone(phoneNumber: String) {
        putString(KEY_ENROLLED_PHONE, phoneNumber)
    }

    fun loadEnrolledPhone(): String? {
        return getString(KEY_ENROLLED_PHONE)
    }

    fun saveEsHostOverride(host: String?) {
        putString(KEY_ES_HOST_OVERRIDE, host?.trim().takeIf { !it.isNullOrBlank() })
    }

    fun saveEsPortOverride(port: Int?) {
        putString(KEY_ES_PORT_OVERRIDE, port?.toString())
    }

    fun saveRsHostOverride(host: String?) {
        putString(KEY_RS_HOST_OVERRIDE, host?.trim().takeIf { !it.isNullOrBlank() })
    }

    fun saveRsPortOverride(port: Int?) {
        putString(KEY_RS_PORT_OVERRIDE, port?.toString())
    }

    fun clearServerOverrides() {
        putString(KEY_ES_HOST_OVERRIDE, null)
        putString(KEY_ES_PORT_OVERRIDE, null)
        putString(KEY_RS_HOST_OVERRIDE, null)
        putString(KEY_RS_PORT_OVERRIDE, null)
    }

    fun getEffectiveEsHost(): String {
        return getString(KEY_ES_HOST_OVERRIDE)?.takeIf { it.isNotBlank() } ?: BuildConfig.ES_HOST
    }

    fun getEffectiveEsPort(): Int {
        return getString(KEY_ES_PORT_OVERRIDE)?.toIntOrNull() ?: BuildConfig.ES_PORT
    }

    fun getEffectiveRsHost(): String {
        return getString(KEY_RS_HOST_OVERRIDE)?.takeIf { it.isNotBlank() } ?: BuildConfig.RS_HOST
    }

    fun getEffectiveRsPort(): Int {
        return getString(KEY_RS_PORT_OVERRIDE)?.toIntOrNull() ?: BuildConfig.RS_PORT
    }

    /**
     * Clears enrollment data.
     */
    fun clearEnrollment() {
        Log.d(TAG, "Clearing enrollment data")
        putString(KEY_DIA_CONFIG, null)
        putString(KEY_ENROLLED_PHONE, null)
        clearAllPeerSessions()
    }
}
