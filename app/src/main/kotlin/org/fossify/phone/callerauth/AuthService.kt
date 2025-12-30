package org.fossify.phone.callerauth

import android.telecom.Call
import android.util.Log
import kotlinx.coroutines.*

/**
 * Authentication service - NEEDS MIGRATION TO LIBDIA V2
 * TODO: Replace primitive-based implementation with LibDia v2 API
 * See: io.github.lokingdav.libdia.CallState and related classes
 */
object AuthService {
    private const val TAG = "CallAuth"

    // Service-wide background scope for network I/O
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Current out-of-band controller for the active call (if any)
    @Volatile private var oob: OobController? = null

    /**
     * TODO: Migrate to LibDia v2 enrollment
     */
    fun enrollNewNumber(
        phoneNumber: String,
        displayName: String,
        logoUrl: String,
        scope: CoroutineScope
    ) {
        Log.d(TAG, "Enrollment not yet migrated to LibDia v2")
        // TODO: Implement using io.github.lokingdav.libdia.Enrollment
    }

    /**
     * TODO: Migrate to LibDia v2 outgoing call flow
     */
    fun startOutgoingCall(recipient: String) {
        Log.d(TAG, "Outgoing call auth not yet migrated to LibDia v2")
        // TODO: Implement using CallState.create() with outgoing=true
    }

    /**
     * TODO: Migrate to LibDia v2 incoming call flow
     */
    fun handleIncomingCall(call: Call): Boolean {
        Log.d(TAG, "Incoming call auth not yet migrated to LibDia v2")
        // TODO: Implement using CallState.create() with outgoing=false
        return true
    }

    /**
     * TODO: Migrate to LibDia v2 on-demand auth
     */
    fun requestOnDemandAuthentication(): Boolean {
        Log.d(TAG, "On-demand auth not yet migrated to LibDia v2")
        return false
    }

    /**
     * Call this when the telephony call ends to close the OOB channel.
     */
    fun endCallCleanup() {
        serviceScope.launch {
            try {
                oob?.close()
            } catch (_: Throwable) { }
            oob = null
        }
    }
}
