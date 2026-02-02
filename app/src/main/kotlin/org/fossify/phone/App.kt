package org.fossify.phone

import android.util.Log
import org.fossify.commons.FossifyApp
import org.fossify.phone.callerauth.RelayChannelPool
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
                    
                    // Pre-warm relay connection to eliminate cold-start latency
                    warmupRelayConnection()
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
        
        /**
         * Pre-warms the relay connection in background to reduce first-call latency.
         */
        private fun warmupRelayConnection() {
            try {
                val host = Storage.getEffectiveRsHost()
                val port = Storage.getEffectiveRsPort()
                Log.d(TAG, "Warming up relay connection to $host:$port")
                RelayChannelPool.warmup(host, port, useTls = false)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to warmup relay connection: ${e.message}")
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
