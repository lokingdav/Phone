package org.fossify.phone.helpers

import android.util.Log

object DenseIdentity {
    fun startOutgoingCall(recipient: String) {
        Log.d("Dense Identity", "Handling call for recipient: $recipient")
    }

    fun requestOnDemandAuthentication(): Boolean {
        Log.d("Dense Identity", "Requesting on-demand authentication.")
        return false
    }
}
