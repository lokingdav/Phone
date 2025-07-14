package org.fossify.phone.helpers

import android.telecom.Call
import android.util.Log
import java.security.KeyPair

object DenseIdentity {
    fun enrollNewNumber(phoneNumber: String, displayName: String, logoUrl: String) {
        val keys = Signing.regSigKeygen()
        val pkStr = Signing.exportPublicKeyToHexString(keys.public);
        Log.d("Dense Identity", "Enrolling new number=$phoneNumber, Display Name=$displayName, Logo URL=$logoUrl, pk=$pkStr")
    }

    fun startOutgoingCall(recipient: String) {
        Log.d("Dense Identity", "Handling call for recipient: $recipient")
    }

    fun requestOnDemandAuthentication(): Boolean {
        Log.d("Dense Identity", "Requesting on-demand authentication.")
        return false
    }

    fun handleIncomingCall(call: Call): Boolean {
        Log.d("Dense Identity", "Handling incoming call.")
        return true
    }
}
