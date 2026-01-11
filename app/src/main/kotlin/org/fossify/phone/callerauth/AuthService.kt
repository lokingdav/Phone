package org.fossify.phone.callerauth

import android.telecom.Call
import android.util.Log
import io.github.lokingdav.libdia.*
import kotlinx.coroutines.*
import org.fossify.phone.App
import org.fossify.phone.BuildConfig

/**
 * Authentication service using LibDia v2 API.
 * Implements AKE (Authenticated Key Exchange) and RUA (Right-to-Use Authentication) protocols.
 * 
 * Flow:
 * CALLER (Alice):
 *   1. akeInit() + subscribe to AKE topic
 *   2. Send AKE_REQUEST
 *   3. Place actual call (triggers Bob)
 *   4. Receive AKE_RESPONSE → akeComplete() → send AKE_COMPLETE
 *   5. Transition to RUA, subscribe to RUA topic with RUA_REQUEST
 *   6. Receive RUA_RESPONSE → ruaFinalize() → verified identity
 * 
 * RECIPIENT (Bob):
 *   1. Receive call signal (don't ring!)
 *   2. akeInit() + subscribe to AKE topic (gets AKE_REQUEST via replay)
 *   3. Receive AKE_REQUEST → akeResponse() → send AKE_RESPONSE
 *   4. Receive AKE_COMPLETE → akeFinalize()
 *   5. Transition to RUA, subscribe to RUA topic
 *   6. ruaInit() + receive RUA_REQUEST → ruaResponse() → send RUA_RESPONSE
 *   7. Ring phone
 */
object AuthService {
    private const val TAG = "CallAuth"
    private const val PROTOCOL_TIMEOUT_MS = 15_000L

    // Service-wide background scope for network I/O
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Current call state and OOB controller (one active call at a time)
    @Volatile private var currentCallState: CallState? = null
    @Volatile private var oobController: OobController? = null
    
    // Callbacks for protocol completion
    @Volatile private var onReadyToCallCallback: (() -> Unit)? = null
    @Volatile private var protocolCompleteCallback: ((Boolean, RemoteParty?) -> Unit)? = null
    @Volatile private var timeoutJob: Job? = null

    /**
     * Enrolls a new subscriber using LibDia v2 enrollment protocol.
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
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "❌ Enrollment failed for $phoneNumber", e)
                onComplete?.invoke(false, e.message ?: "Unknown error")
            }
        }
    }

    /**
     * Starts authentication for an outgoing call (Caller/Alice flow).
     * 
     * 1. Initializes AKE and subscribes to AKE topic
     * 2. Sends AKE_REQUEST
     * 3. Calls onReadyToCall - UI should place actual telephony call now
     * 4. Waits for AKE_RESPONSE, completes AKE, transitions to RUA
     * 5. Waits for RUA_RESPONSE, calls onProtocolComplete with verified identity
     */
    fun startOutgoingCall(
        recipient: String,
        onReadyToCall: () -> Unit,
        onProtocolComplete: (success: Boolean, remoteParty: RemoteParty?) -> Unit
    ) {
        serviceScope.launch {
            try {
                Log.d(TAG, "▶ Starting outgoing call protocol to $recipient")
                
                // Clean up any stale state from previous call
                if (currentCallState != null || oobController != null) {
                    Log.w(TAG, "Cleaning up stale state from previous call")
                    cleanupSync()
                }
                
                val config = App.diaConfig
                if (config == null) {
                    Log.e(TAG, "No DiaConfig - user not enrolled")
                    withContext(Dispatchers.Main) { onProtocolComplete(false, null) }
                    return@launch
                }

                // Create call state for outgoing call
                val callState = CallState.create(config, recipient, outgoing = true)
                currentCallState = callState
                
                // Initialize AKE (generates DH keys, computes AKE topic)
                callState.akeInit()
                
                // Get OOB channel parameters
                val akeTopic = callState.akeTopic
                val ticket = callState.ticket
                val senderID = callState.senderId
                
                Log.d(TAG, "AKE initialized - topic: $akeTopic, senderID: $senderID")
                
                // Store callbacks
                onReadyToCallCallback = onReadyToCall
                protocolCompleteCallback = onProtocolComplete
                
                // Start OOB channel on AKE topic
                val oob = OobController(
                    relayHost = BuildConfig.RS_HOST,
                    relayPort = BuildConfig.RS_PORT,
                    initialTopic = akeTopic,
                    ticket = ticket,
                    senderID = senderID,
                    scope = serviceScope,
                    useTls = false,
                    heartbeatProvider = { callState.createHeartbeatMessage() }
                )
                
                oob.start { payload: ByteArray -> handleOobMessage(payload) }
                // Note: Heartbeat will be started after protocol completes
                oobController = oob
                
                // Send AKE request
                val akeRequest = callState.akeRequest()
                oob.send(akeRequest)
                Log.d(TAG, "Sent AKE_REQUEST (${akeRequest.size} bytes)")
                
                // Signal that call can now be placed
                withContext(Dispatchers.Main) {
                    onReadyToCallCallback?.invoke()
                    onReadyToCallCallback = null
                }
                Log.d(TAG, "Call can now be placed, waiting for AKE_RESPONSE...")
                
                // Set timeout for protocol completion
                startProtocolTimeout()
                
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to start outgoing call protocol", e)
                cleanup()
                onProtocolComplete(false, null)
            }
        }
    }

    /**
     * Handles an incoming call (Recipient/Bob flow).
     * 
     * 1. Initializes AKE and subscribes to AKE topic (gets AKE_REQUEST via replay)
     * 2. Receives AKE_REQUEST → sends AKE_RESPONSE
     * 3. Receives AKE_COMPLETE → finalizes AKE
     * 4. Transitions to RUA, receives RUA_REQUEST → sends RUA_RESPONSE
     * 5. Calls onProtocolComplete - UI should ring phone now
     */
    fun handleIncomingCall(
        call: Call,
        onProtocolComplete: (success: Boolean, remoteParty: RemoteParty?) -> Unit
    ) {
        serviceScope.launch {
            try {
                Log.d(TAG, "▶ Received call signal, starting protocol (not ringing yet)")
                
                // Clean up any stale state from previous call
                if (currentCallState != null || oobController != null) {
                    Log.w(TAG, "Cleaning up stale state from previous call")
                    cleanupSync()
                }
                
                val config = App.diaConfig
                if (config == null) {
                    Log.e(TAG, "No DiaConfig - user not enrolled")
                    withContext(Dispatchers.Main) { onProtocolComplete(false, null) }
                    return@launch
                }

                // Get caller number from call
                val callerNumber = call.details?.handle?.schemeSpecificPart ?: ""
                if (callerNumber.isEmpty()) {
                    Log.w(TAG, "No caller number available")
                    withContext(Dispatchers.Main) { onProtocolComplete(false, null) }
                    return@launch
                }
                
                Log.d(TAG, "Caller: $callerNumber")
                
                // Create call state for incoming call
                val callState = CallState.create(config, callerNumber, outgoing = false)
                currentCallState = callState
                
                // Initialize AKE (generates DH keys, computes AKE topic)
                callState.akeInit()
                
                // Get OOB channel parameters
                val akeTopic = callState.akeTopic
                val ticket = callState.ticket
                val senderID = callState.senderId
                
                Log.d(TAG, "AKE initialized - topic: $akeTopic, senderID: $senderID")
                
                // Store callback
                protocolCompleteCallback = onProtocolComplete
                
                // Start OOB channel on AKE topic (will receive AKE_REQUEST via replay)
                val oob = OobController(
                    relayHost = BuildConfig.RS_HOST,
                    relayPort = BuildConfig.RS_PORT,
                    initialTopic = akeTopic,
                    ticket = ticket,
                    senderID = senderID,
                    scope = serviceScope,
                    useTls = false,
                    heartbeatProvider = { callState.createHeartbeatMessage() }
                )
                
                oob.start { payload: ByteArray -> handleOobMessage(payload) }
                // Note: Heartbeat will be started after protocol completes
                oobController = oob
                
                Log.d(TAG, "Subscribed to AKE topic, waiting for AKE_REQUEST...")
                
                // Set timeout for protocol completion
                startProtocolTimeout()
                
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to handle incoming call protocol", e)
                cleanup()
                onProtocolComplete(false, null)
            }
        }
    }

    /**
     * Handles incoming OOB messages and routes to appropriate handler.
     */
    private fun handleOobMessage(payload: ByteArray) {
        serviceScope.launch {
            try {
                val callState = currentCallState
                if (callState == null) {
                    Log.w(TAG, "Received OOB message but no active call state")
                    return@launch
                }
                
                Log.d(TAG, "Processing OOB message (${payload.size} bytes)")
                
                // Parse message (use() auto-closes the handle)
                DiaMessage.parse(payload).use { message ->
                    val msgSenderId = message.senderId
                    val msgTopic = message.topic
                    val msgType = message.type
                    val myTopic = callState.currentTopic
                    val mySenderId = callState.senderId
                    
                    Log.d(TAG, "Message: type=$msgType sender=$msgSenderId topic=$msgTopic")
                    Log.d(TAG, "My state: sender=$mySenderId topic=$myTopic isCaller=${callState.isCaller}")
                    
                    // Self-echo suppression
                    if (msgSenderId == mySenderId) {
                        Log.d(TAG, "Ignoring self-authored message")
                        return@use
                    }

                    // Always honor BYE even if topic mismatches due to in-flight switching
                    if (msgType == MSG_BYE) {
                        Log.d(TAG, "Received BYE message - ending call")
                        endCallCleanup()
                        return@use
                    }

                    // Heartbeats are allowed on any topic; ignore them
                    if (msgType == MSG_HEARTBEAT) {
                        Log.v(TAG, "Received HEARTBEAT message")
                        return@use
                    }
                    
                    // Topic validation - only filter if topics don't match
                    // Note: During topic transitions, we may receive messages from the old topic
                    if (msgTopic.isNotEmpty() && myTopic.isNotEmpty() && msgTopic != myTopic) {
                        Log.d(TAG, "Ignoring message from inactive topic: $msgTopic (current: $myTopic)")
                        return@use
                    }
                    
                    Log.d(TAG, "✓ Accepted message type=$msgType")
                    
                    // Route based on role
                    if (callState.isCaller) {
                        handleCallerMessage(callState, msgType, payload)
                    } else if (callState.isRecipient) {
                        handleRecipientMessage(callState, msgType, payload)
                    }
                }
                
            } catch (e: Exception) {
                Log.e(TAG, "Error handling OOB message", e)
            }
        }
    }

    // ==================== CALLER (Alice) Message Handlers ====================

    /**
     * Handles messages for the caller (Alice).
     */
    private suspend fun handleCallerMessage(callState: CallState, msgType: Int, rawData: ByteArray) {
        when (msgType) {
            MSG_AKE_RESPONSE -> handleCallerAkeResponse(callState, rawData)
            MSG_RUA_RESPONSE -> handleCallerRuaResponse(callState, rawData)
            else -> Log.w(TAG, "Caller received unexpected message type: $msgType")
        }
    }

    /**
     * Caller handles AKE_RESPONSE from recipient.
     */
    private suspend fun handleCallerAkeResponse(callState: CallState, rawData: ByteArray) {
        try {
            Log.d(TAG, "Processing AKE_RESPONSE...")
            
            // Save old AKE topic
            val oldAkeTopic = callState.currentTopic
            
            // Process response → get AKE_COMPLETE message and shared key
            val completeMsg = callState.akeComplete(rawData)
            Log.d(TAG, "✓ AKE Complete! Shared key established")

            // Send AKE_COMPLETE ASAP on the old AKE topic so the recipient can finalize before we switch topics.
            // (Matches denseid sipcontroller ordering.)
            oobController?.sendToTopic(oldAkeTopic, completeMsg)
            Log.d(TAG, "Sent AKE_COMPLETE on old topic")
            
            // Derive RUA topic
            val ruaTopic = callState.ruaDeriveTopic()
            Log.d(TAG, "RUA topic derived: $ruaTopic")
            
            // Create RUA request before transitioning
            val ruaRequest = callState.ruaRequest()
            
            // Get ticket for topic creation
            val ticket = callState.ticket
            
            // Transition to RUA state
            callState.transitionToRua()

            // Subscribe to RUA topic with piggyback RUA request
            oobController?.subscribeToNewTopic(ruaTopic, ruaRequest, ticket)
            Log.d(TAG, "Subscribed to RUA topic with RUA_REQUEST")
            
            Log.d(TAG, "Waiting for RUA_RESPONSE...")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle AKE_RESPONSE", e)
            failProtocol()
        }
    }

    /**
     * Caller handles RUA_RESPONSE from recipient - protocol complete!
     */
    private suspend fun handleCallerRuaResponse(callState: CallState, rawData: ByteArray) {
        try {
            Log.d(TAG, "Processing RUA_RESPONSE...")
            
            // Finalize RUA
            callState.ruaFinalize(rawData)
            
            // Get verified remote party
            val remoteParty = callState.remoteParty
            Log.d(TAG, "✓✓✓ PROTOCOL COMPLETE! Verified: ${remoteParty.name} (${remoteParty.phone})")
            
            // Cancel timeout
            timeoutJob?.cancel()
            timeoutJob = null
            
            // Start heartbeat now that protocol is complete
            oobController?.startHeartbeat()
            
            // Signal protocol complete
            withContext(Dispatchers.Main) {
                protocolCompleteCallback?.invoke(true, remoteParty)
                protocolCompleteCallback = null
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle RUA_RESPONSE", e)
            failProtocol()
        }
    }

    // ==================== RECIPIENT (Bob) Message Handlers ====================

    /**
     * Handles messages for the recipient (Bob).
     */
    private suspend fun handleRecipientMessage(callState: CallState, msgType: Int, rawData: ByteArray) {
        when (msgType) {
            MSG_AKE_REQUEST -> handleRecipientAkeRequest(callState, rawData)
            MSG_AKE_COMPLETE -> handleRecipientAkeComplete(callState, rawData)
            MSG_RUA_REQUEST -> handleRecipientRuaRequest(callState, rawData)
            else -> Log.w(TAG, "Recipient received unexpected message type: $msgType")
        }
    }

    /**
     * Recipient handles AKE_REQUEST from caller.
     */
    private suspend fun handleRecipientAkeRequest(callState: CallState, rawData: ByteArray) {
        try {
            Log.d(TAG, "Processing AKE_REQUEST...")
            
            // Create and send AKE response
            val response = callState.akeResponse(rawData)
            oobController?.send(response)
            Log.d(TAG, "Sent AKE_RESPONSE (${response.size} bytes)")
            
            Log.d(TAG, "Waiting for AKE_COMPLETE...")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle AKE_REQUEST", e)
            failProtocol()
        }
    }

    /**
     * Recipient handles AKE_COMPLETE from caller.
     */
    private suspend fun handleRecipientAkeComplete(callState: CallState, rawData: ByteArray) {
        try {
            Log.d(TAG, "Processing AKE_COMPLETE...")
            
            // Finalize AKE
            callState.akeFinalize(rawData)
            Log.d(TAG, "✓ AKE Complete! Shared key established")
            
            // Derive RUA topic
            val ruaTopic = callState.ruaDeriveTopic()
            Log.d(TAG, "RUA topic derived: $ruaTopic")
            
            // Transition to RUA state
            callState.transitionToRua()
            
            // Subscribe to RUA topic (with replay to get RUA_REQUEST)
            oobController?.subscribeToNewTopic(ruaTopic, piggybackMessage = null, ticket = callState.ticket)
            Log.d(TAG, "Subscribed to RUA topic")
            
            // Initialize RUA
            callState.ruaInit()
            Log.d(TAG, "RUA initialized, waiting for RUA_REQUEST...")
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle AKE_COMPLETE", e)
            failProtocol()
        }
    }

    /**
     * Recipient handles RUA_REQUEST from caller - protocol complete!
     */
    private suspend fun handleRecipientRuaRequest(callState: CallState, rawData: ByteArray) {
        try {
            Log.d(TAG, "Processing RUA_REQUEST...")
            
            // Create and send RUA response
            val response = callState.ruaResponse(rawData)
            oobController?.send(response)
            Log.d(TAG, "Sent RUA_RESPONSE (${response.size} bytes)")
            
            // Get verified remote party
            val remoteParty = callState.remoteParty
            Log.d(TAG, "✓✓✓ PROTOCOL COMPLETE! Verified: ${remoteParty.name} (${remoteParty.phone})")
            
            // Cancel timeout
            timeoutJob?.cancel()
            timeoutJob = null
            
            // Start heartbeat now that protocol is complete
            oobController?.startHeartbeat()
            
            // Signal protocol complete - phone can ring now!
            withContext(Dispatchers.Main) {
                protocolCompleteCallback?.invoke(true, remoteParty)
                protocolCompleteCallback = null
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Failed to handle RUA_REQUEST", e)
            failProtocol()
        }
    }

    // ==================== Utility Functions ====================

    /**
     * Starts protocol timeout timer.
     */
    private fun startProtocolTimeout() {
        timeoutJob?.cancel()
        timeoutJob = serviceScope.launch {
            delay(PROTOCOL_TIMEOUT_MS)
            Log.w(TAG, "Protocol timeout after ${PROTOCOL_TIMEOUT_MS}ms")
            failProtocol()
        }
    }

    /**
     * Called when protocol fails - notify callback and cleanup.
     */
    private suspend fun failProtocol() {
        Log.d(TAG, "failProtocol called - notifying callbacks and cleaning up")
        timeoutJob?.cancel()
        timeoutJob = null
        
        withContext(Dispatchers.Main) {
            protocolCompleteCallback?.invoke(false, null)
            protocolCompleteCallback = null
            onReadyToCallCallback = null
        }
        
        cleanupSync()  // Use sync cleanup to avoid double cleanup
        Log.d(TAG, "failProtocol completed")
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
     * Synchronous cleanup for use within a coroutine.
     */
    private suspend fun cleanupSync() {
        try {
            Log.d(TAG, "Synchronous cleanup of call auth resources")
            timeoutJob?.cancel()
            timeoutJob = null
            oobController?.stopHeartbeat()
            oobController?.close()
            currentCallState?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error during sync cleanup", e)
        } finally {
            oobController = null
            currentCallState = null
            protocolCompleteCallback = null
            onReadyToCallCallback = null
        }
    }

    /**
     * Internal cleanup helper.
     */
    private suspend fun cleanup() {
        try {
            Log.d(TAG, "Cleaning up call auth resources")
            timeoutJob?.cancel()
            timeoutJob = null
            
            // Send BYE message before closing
            try {
                val callState = currentCallState
                val oob = oobController
                if (callState != null && oob != null) {
                    val byeMessage = callState.createByeMessage()
                    oob.send(byeMessage)
                    Log.d(TAG, "Sent BYE message")
                    // Small delay to allow message to be sent
                    delay(100)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to send BYE message: ${e.message}")
            }
            
            oobController?.stopHeartbeat()
            oobController?.close()
            currentCallState?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error during cleanup", e)
        } finally {
            oobController = null
            currentCallState = null
            protocolCompleteCallback = null
            onReadyToCallCallback = null
        }
    }
}
