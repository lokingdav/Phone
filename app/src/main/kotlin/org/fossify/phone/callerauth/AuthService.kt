package org.fossify.phone.callerauth

import android.telecom.Call
import android.util.Log
import kotlinx.coroutines.*
import org.fossify.phone.BuildConfig

object AuthService {
    private const val TAG = "CallAuth"
    private const val RELAY_USE_TLS = false

    // Service-wide background scope for network I/O
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Current out-of-band controller for the active call (if any)
    @Volatile private var oob: OobController? = null

    // Remember who we're talking to for topic derivation (simple POC)
    @Volatile private var currentPeerE164: String? = null
    @Volatile private var currentTopic: String? = null

    /**
     * Generates a signing keypair, exports the public key to hex,
     * and delegates the parallel enrollment calls.
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
                phoneNumber = phoneNumber,
                displayName = displayName,
                logoUrl = logoUrl
            )
        }
    }

    /**
     * Outgoing call entrypoint: derive a topic + ticket, start OOB stream,
     * and (optionally) send an initial “hello/auth-init” payload.
     */
    fun startOutgoingCall(recipient: String) {
        try {
            val callerId = UserState.display.phoneNumber // e.g., "+15551234567"
            Log.d(TAG, "Start outgoing call with callerId ($callerId) to recipient ($recipient)")

            // Build a simple per-call topic. For POC, concatenate parties + epoch second.
            val topic = "call:${callerId}->${recipient}:${System.currentTimeMillis()/1000}"
            val ticket = UserState.popTicket()

            startOob(topic, ticket)

            // Optional: send an initial AUTH_INIT frame (keep it simple—raw bytes/string)
            serviceScope.launch {
                val init = "AUTH_INIT|from=$callerId"
                val ok = oob?.send(init.toByteArray(Charsets.UTF_8)) ?: false
                Log.d(TAG, "Sent AUTH_INIT: $ok")
            }

            currentPeerE164 = recipient
            currentTopic = topic
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start outgoing call", e)
        }
    }

    /**
     * Incoming call entrypoint: similar to outgoing—choose a topic and start OOB.
     * You can use Call details if you want; for POC we just use caller E.164.
     */
    fun handleIncomingCall(call: Call): Boolean {
        return try {
            Log.d(TAG, "Handling incoming call.")

            val myNumber = UserState.display.phoneNumber
            val remote = extractRemoteNumber(call) ?: "unknown"
            val topic = "call:${remote}->${myNumber}:${System.currentTimeMillis()/1000}"

            startOob(topic, null)

            currentPeerE164 = remote
            currentTopic = topic
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle incoming call", e)
            false
        }
    }

    /**
     * Mid-call on-demand authentication request. Returns true if the send succeeded.
     */
    fun requestOnDemandAuthentication(): Boolean {
        return try {
            val peer = currentPeerE164 ?: return false.also {
                Log.w(TAG, "No active peer; cannot request auth.")
            }
            val msg = "AUTH_REQUEST|peer=$peer"
            var result = false
            runBlocking(serviceScope.coroutineContext) {
                result = oob?.send(msg.toByteArray(Charsets.UTF_8)) ?: false
            }
            Log.d(TAG, "Requested on-demand authentication: $result")
            result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to request on-demand authentication", e)
            false
        }
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
            currentPeerE164 = null
            currentTopic = null
        }
    }

    // --- Internal helpers ---

    private fun startOob(topic: String, ticket: ByteArray?) {
        // If an old session exists, close it before starting a new one
        serviceScope.launch {
            try { oob?.close() } catch (_: Throwable) { }
        }

        val controller = OobController(
            host = BuildConfig.RS_HOST,
            port = BuildConfig.RS_PORT,
            topic = topic,
            ticket = ticket,
            scope = serviceScope,
            useTls = RELAY_USE_TLS
        )

        controller.start { bytes ->
            val text = bytes.toString(Charsets.UTF_8)
            Log.d(TAG, "OOB inbound: $text")

            // Minimal example routing:
            // AUTH_INIT, AUTH_REQUEST, AUTH_RESPONSE, EVENT, etc.
            when {
                text.startsWith("AUTH_REQUEST") -> {
                    // Respond with a simple acceptance (replace with your real payload)
                    serviceScope.launch {
                        val ok = oob?.send("AUTH_RESPONSE|ok=true".toByteArray()) ?: false
                        Log.d(TAG, "Sent AUTH_RESPONSE: $ok")
                    }
                }
                // add more cases as needed
            }
        }

        oob = controller
    }

    private fun extractRemoteNumber(call: Call): String? {
        // Minimal placeholder. In a real implementation, parse from call.details.
        return call.details.handle.schemeSpecificPart
    }
}
