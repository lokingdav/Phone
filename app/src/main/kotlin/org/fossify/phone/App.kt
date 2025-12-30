package org.fossify.phone

import android.util.Log
import org.fossify.commons.FossifyApp
import org.fossify.phone.callerauth.Storage
import io.github.lokingdav.libdia.DiaConfig

class App : FossifyApp() {
    companion object {
        private const val TAG = "CallAuth-App"
        
        /**
         * Global DiaConfig instance, null if not enrolled.
         * Initialized on app startup from saved enrollment data.
         */
        var diaConfig: DiaConfig? = null
            private set
    }
    
    override fun onCreate() {
        super.onCreate()

        Storage.init(this)
        
        // Load saved DiaConfig if user is enrolled
        val savedEnv = Storage.loadDiaConfig()
        if (savedEnv != null) {
            try {
                Log.d(TAG, "Loading saved DiaConfig from storage...")
                diaConfig = DiaConfig.fromEnv(savedEnv)
                Log.d(TAG, "✓ DiaConfig loaded successfully")
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to load DiaConfig from storage", e)
                // Clear corrupted data
                Storage.clearEnrollment()
            }
        } else {
            Log.d(TAG, "No saved enrollment data found")
        }
    }
}
