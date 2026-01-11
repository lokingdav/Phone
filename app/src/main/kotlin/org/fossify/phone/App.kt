package org.fossify.phone

import android.util.Log
import org.fossify.commons.FossifyApp
import org.fossify.phone.callerauth.Storage
import org.fossify.phone.metrics.MetricsRecorder
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
        
        /**
         * Reloads DiaConfig from storage. Call this after enrollment changes.
         */
        fun reloadDiaConfig() {
            val savedEnv = Storage.loadDiaConfig()
            if (savedEnv != null) {
                try {
                    Log.d(TAG, "Reloading DiaConfig from storage...")
                    diaConfig?.close() // Close old config if it exists
                    diaConfig = DiaConfig.fromEnv(savedEnv)
                    Log.d(TAG, "✓ DiaConfig reloaded successfully")
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Failed to reload DiaConfig from storage", e)
                    diaConfig = null
                    Storage.clearEnrollment()
                }
            } else {
                Log.d(TAG, "No saved enrollment data found")
                diaConfig?.close()
                diaConfig = null
            }
        }
    }
    
    override fun onCreate() {
        super.onCreate()

        Storage.init(this)
        MetricsRecorder.init(this)
        
        // Load saved DiaConfig if user is enrolled
        reloadDiaConfig()
    }
}
