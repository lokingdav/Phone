package org.fossify.phone.callerauth

import android.telecom.Call
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

object AuthService {
    private const val TAG = "CallAuth"

    /**
     * Generates a signing keypair, exports the public key to hex,
     * and delegates the parallel enrollment calls.
     *
     * @param phoneNumber E.164 number, e.g. "+15551234567"
     * @param displayName Human‐readable subscriber name
     * @param logoUrl     HTTPS URL to an avatar/logo
     * @param scope       CoroutineScope (e.g. Fragment.lifecycleScope)
     */
    fun enrollNewNumber(
        phoneNumber: String,
        displayName: String,
        logoUrl: String,
        scope: CoroutineScope
    ) {
        Log.d(TAG, "Enrolling new number: $phoneNumber")
        scope.launch(Dispatchers.IO) {
            ManageEnrollment.enroll(
                phoneNumber   = phoneNumber,
                displayName   = displayName,
                logoUrl       = logoUrl
            )
        }
    }

    fun startOutgoingCall(recipient: String) {
        try {
            val callerId = UserState.display.phoneNumber
            Log.d(TAG, "Start outgoing call with callerId ($callerId) to recipient ($recipient)")
            val secretKey = KeyDerivation.run(callerId)
            Log.d(TAG, "Secret key: ${Signing.encodeToHex(secretKey)}")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start outgoing call", e)
        }
    }

    fun requestOnDemandAuthentication(): Boolean {
        try {
            Log.d(TAG, "Requesting on-demand authentication.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to request on-demand authentication", e)
        }
        return false
    }

    fun handleIncomingCall(call: Call): Boolean {
        try {
            Log.d(TAG, "Handling incoming call.")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle incoming call", e)
        }
        return true
    }
}
