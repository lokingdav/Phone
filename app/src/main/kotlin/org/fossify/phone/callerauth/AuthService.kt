package org.fossify.phone.callerauth

import android.telecom.Call
import android.util.Log
import io.github.lokingdav.libdia.CallState
import io.github.lokingdav.libdia.DiaMessage
import kotlinx.coroutines.*
import org.fossify.phone.App
import org.fossify.phone.BuildConfig

/**
 * Authentication service using LibDia v2 API.
 * Manages call authentication lifecycle and OOB channel.
 */
object AuthService {
    private const val TAG = "CallAuth"

    // Service-wide background scope for network I/O
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Current call state and OOB controller (one active call at a time)
    @Volatile private var currentCallState: CallState? = null
    @Volatile private var oobController: OobController? = null
    @Volatile private var onDemandAuthCallback: ((Boolean, String?) -> Unit)? = null

    /**
     * Enrolls a new subscriber using LibDia v2 enrollment protocol.
     * Uses serviceScope to survive UI lifecycle changes.
     */
    fun enrollNewNumber(
        phoneNumber: String,
        displayName: String,
        logoUrl: String,
        onComplete: ((success: Boolean, error: String?) -> Unit)? = null
    ) {
        serviceScope.launch {
            try {
                Log.d(TAG, "▶ Starting enrollment for $phoneNumber")
                ManageEnrollment.enroll(phoneNumber, displayName, logoUrl)
                Log.d(TAG, "✅ Enrollment completed successfully")
                onComplete?.invoke(true, null)
            } catch (e: CancellationException) {
                Log.d(TAG, "Enrollment coroutine cancelled for $phoneNumber")
                throw e // Re-throw to propagate cancellation
            } catch (e: Exception) {
                Log.e(TAG, "❌ Enrollment failed for $phoneNumber", e)
                onComplete?.invoke(false, e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Starts authentication for an outgoing call.
     * Creates CallState, establishes OOB channel, and begins heartbeat.
     */
    fun startOutgoingCall(recipient: String, onResult: ((Boolean, String?) -> Unit)? = null) {
        serviceScope.launch {
            try {
                Log.d(TAG, "▶ Starting outgoing call auth to $recipient")
                
                val config = App.diaConfig
                if (config == null) {
                    Log.e(TAG, "No DiaConfig - user not enrolled")
                    onResult?.invoke(false, "Not enrolled")
                    return@launch
                }

                // Create call state for outgoing call
                val callState = CallState.create(config, recipient, outgoing = true)
                currentCallState = callState
                
                // Get OOB channel parameters
                val topic = callState.currentTopic()
                val ticket = callState.ticket()
                val senderID = callState.senderID()
                
                Log.d(TAG, "Call state created - topic: $topic, senderID: $senderID")
                
                // Start OOB channel
                val oob = OobController(
                    relayHost = BuildConfig.RELAY_HOST,
                    relayPort = BuildConfig.RELAY_PORT,
                    initialTopic = topic,
                    ticket = ticket,
                    senderID = senderID,
                    scope = serviceScope,
                    useTls = false // TODO: Use TLS in production
                )
                
                oob.start { payload -> handleOobMessage(payload) }
                oob.startHeartbeat()
                oobController = oob
                
                Log.d(TAG, "✅ Outgoing call auth started")
                onResult?.invoke(true, null)
                
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to start outgoing call auth", e)
                cleanup()
                onResult?.invoke(false, e.message)
            }
        }
    }

    /**
     * Handles an incoming call.
     * Creates CallState, establishes OOB channel, and begins heartbeat.
     */
    fun handleIncomingCall(call: Call, onResult: ((Boolean, String?) -> Unit)? = null) {
        serviceScope.launch {
            try {
                Log.d(TAG, "▶ Handling incoming call")
                
                val config = App.diaConfig
                if (config == null) {
                    Log.e(TAG, "No DiaConfig - user not enrolled")
                    onResult?.invoke(false, "Not enrolled")
                    return@launch
                }

                // Get caller number from call
                val callerNumber = call.details?.handle?.schemeSpecificPart ?: ""
                if (callerNumber.isEmpty()) {
                    Log.w(TAG, "No caller number available")
                    onResult?.invoke(false, "No caller number")
                    return@launch
                }
                
                // Create call state for incoming call
                val callState = CallState.create(config, callerNumber, outgoing = false)
                currentCallState = callState
                
                // Get OOB channel parameters
                val topic = callState.currentTopic()
                val ticket = callState.ticket()
                val senderID = callState.senderID()
                
                Log.d(TAG, "Call state created - topic: $topic, senderID: $senderID")
                
                // Start OOB channel
                val oob = OobController(
                    relayHost = BuildConfig.RELAY_HOST,
                    relayPort = BuildConfig.RELAY_PORT,
                    initialTopic = topic,
                    ticket = ticket,
                    senderID = senderID,
                    scope = serviceScope,
                    useTls = false // TODO: Use TLS in production
                )
                
                oob.start { payload -> handleOobMessage(payload) }
                oob.startHeartbeat()
                oobController = oob
                
                Log.d(TAG, "✅ Incoming call auth started")
                onResult?.invoke(true, null)
                
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to handle incoming call", e)
                cleanup()
                onResult?.invoke(false, e.message)
            }
        }
    }

    /**
     * Requests on-demand authentication during an active call.
     * Sends auth request message through OOB channel and waits for response.
     */
    fun requestOnDemandAuthentication(onResult: (Boolean, String?) -> Unit) {
        serviceScope.launch {
            try {
                Log.d(TAG, "▶ Requesting on-demand authentication")
                
                val callState = currentCallState
                val oob = oobController
                
                if (callState == null || oob == null) {
                    Log.e(TAG, "No active call for on-demand auth")
                    onResult(false, "No active call")
                    return@launch
                }
                
                // Set callback for auth response
                onDemandAuthCallback = onResult
                
                // Create auth request message using CallState
                val authRequest = callState.createAuthRequest()
                Log.d(TAG, "Sending auth request (${authRequest.size} bytes)")
                
                // Send through OOB channel
                oob.send(authRequest)
                
                // Timeout for response
                launch {
                    delay(10_000) // 10 second timeout
                    if (onDemandAuthCallback != null) {
                        Log.w(TAG, "Auth request timed out")
                        onDemandAuthCallback?.invoke(false, "Timeout")
                        onDemandAuthCallback = null
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to request on-demand auth", e)
                onDemandAuthCallback = null
                onResult(false, e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Handles incoming OOB messages (auth requests/responses, protocol messages).
     */
    private fun handleOobMessage(payload: ByteArray) {
        serviceScope.launch {
            try {
                Log.d(TAG, "Received OOB message (${payload.size} bytes)")
                
                val callState = currentCallState
                if (callState == null) {
                    Log.w(TAG, "Received OOB message but no active call state")
                    return@launch
                }
                
                // Parse message using LibDia
                val message = DiaMessage.parse(payload)
                
                when (message.type) {
                    io.github.lokingdav.libdia.MSG_AKE_REQUEST -> {
                        Log.d(TAG, "Received AKE_REQUEST")
                        handleAuthRequest(callState, message)
                    }
                    
                    io.github.lokingdav.libdia.MSG_AKE_RESPONSE -> {
                        Log.d(TAG, "Received AKE_RESPONSE")
                        handleAuthResponse(callState, message)
                    }
                    
                    io.github.lokingdav.libdia.MSG_RUA_REQUEST -> {
                        Log.d(TAG, "Received RUA_REQUEST (on-demand auth request)")
                        handleOnDemandAuthRequest(callState, message)
                    }
                    
                    io.github.lokingdav.libdia.MSG_RUA_RESPONSE -> {
                        Log.d(TAG, "Received RUA_RESPONSE (on-demand auth response)")
                        handleOnDemandAuthResponse(callState, message)
                    }
                    
                    else -> {
                        Log.w(TAG, "Unknown message type: ${message.type}")
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error handling OOB message", e)
            }
        }
    }

    /**
     * Handles incoming auth request (AKE_REQUEST).
     */
    private suspend fun handleAuthRequest(callState: CallState, message: DiaMessage) {
        try {
            val response = callState.respondToAuthRequest(message.data)
            Log.d(TAG, "Sending AKE_RESPONSE (${response.size} bytes)")
            oobController?.send(response)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to respond to auth request", e)
        }
    }

    /**
     * Handles incoming auth response (AKE_RESPONSE).
     */
    private suspend fun handleAuthResponse(callState: CallState, message: DiaMessage) {
        try {
            val verified = callState.verifyAuthResponse(message.data)
            Log.d(TAG, "Auth response verified: $verified")
            // TODO: Update UI with verification result
        } catch (e: Exception) {
            Log.e(TAG, "Failed to verify auth response", e)
        }
    }

    /**
     * Handles incoming on-demand auth request (RUA_REQUEST).
     */
    private suspend fun handleOnDemandAuthRequest(callState: CallState, message: DiaMessage) {
        try {
            val response = callState.respondToOnDemandAuth(message.data)
            Log.d(TAG, "Sending RUA_RESPONSE (${response.size} bytes)")
            oobController?.send(response)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to respond to on-demand auth", e)
        }
    }

    /**
     * Handles incoming on-demand auth response (RUA_RESPONSE).
     */
    private suspend fun handleOnDemandAuthResponse(callState: CallState, message: DiaMessage) {
        try {
            val verified = callState.verifyOnDemandAuthResponse(message.data)
            Log.d(TAG, "On-demand auth response verified: $verified")
            
            // Invoke callback if waiting for response
            val callback = onDemandAuthCallback
            if (callback != null) {
                callback(verified, if (verified) null else "Verification failed")
                onDemandAuthCallback = null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to verify on-demand auth response", e)
            onDemandAuthCallback?.invoke(false, e.message)
            onDemandAuthCallback = null
        }
    }

    /**
     * Cleans up when the call ends.
     */
    fun endCallCleanup() {
        serviceScope.launch {
            cleanup()
        }
    }

    /**
     * Internal cleanup helper.
     */
    private suspend fun cleanup() {
        try {
            Log.d(TAG, "Cleaning up call auth resources")
            oobController?.stopHeartbeat()
            oobController?.close()
            currentCallState?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error during cleanup", e)
        } finally {
            oobController = null
            currentCallState = null
            onDemandAuthCallback = null
        }
    }
}
        }
    }
}
