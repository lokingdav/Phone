package org.fossify.phone.helpers

import android.telecom.Call
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

object DenseIdentity {
    private const val TAG = "DenseIdentity"

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
        scope.launch(Dispatchers.IO) {
            ManageEnrollment.enroll(
                phoneNumber   = phoneNumber,
                displayName   = displayName,
                logoUrl       = logoUrl
            )
        }
    }

    fun startOutgoingCall(recipient: String) {
        Log.d(TAG, "Handling call for recipient: $recipient")
    }

    fun requestOnDemandAuthentication(): Boolean {
        Log.d(TAG, "Requesting on-demand authentication.")
        return false
    }

    fun handleIncomingCall(call: Call): Boolean {
        Log.d(TAG, "Handling incoming call.")
        return true
    }
}
