package org.fossify.phone.callerauth

import android.telecom.Call
import android.util.Log
import io.github.lokingdav.libdia.*
import kotlinx.coroutines.*
import org.fossify.phone.App
import org.fossify.phone.BuildConfig
import org.fossify.phone.helpers.CallManager
import org.fossify.phone.metrics.MetricsRecorder
import java.util.concurrent.atomic.AtomicBoolean

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
    private const val ODA_TIMEOUT_MS = 15_000L
    private const val AUTO_ODA_DELAY_MS = 1_000L

    // Service-wide background scope for network I/O
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Current call state and OOB controller (one active call at a time)
    @Volatile private var currentCallState: CallState? = null
    @Volatile private var oobController: OobController? = null

    // Per-call mode/state
    @Volatile private var ruaOnlyMode: Boolean = false
    @Volatile private var currentPeerKey: String? = null

    // RUA completion gate for ODA
    @Volatile private var ruaComplete: Boolean = false

    // ODA in-flight state (allow multiple ODAs over call lifetime, but only one at a time)
    private val odaInFlight = AtomicBoolean(false)
    @Volatile private var odaInFlightIsAuto: Boolean = false
    @Volatile private var odaTimeoutJob: Job? = null
    @Volatile private var odaResultCallback: ((OdaVerification) -> Unit)? = null
    @Volatile private var odaErrorCallback: ((String) -> Unit)? = null

    // Auto ODA coordination (best-effort; never blocks or changes core call behavior)
    @Volatile private var autoOdaScheduledJob: Job? = null
    
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

                val peerKey = normalizePhone(recipient)
                currentPeerKey = peerKey
                val cacheEnabled = Storage.isPeerSessionCacheEnabled()
                val cachedSession = if (cacheEnabled) Storage.loadPeerSession(peerKey) else null

                // Create call state for outgoing call
                val callState = CallState.create(config, recipient, outgoing = true)
                currentCallState = callState

                resetSessionState()

                if (cachedSession != null) {
                    ruaOnlyMode = true
                    Log.d(TAG, "Using cached peer session ($peerKey) - running RUA-only")

                    callState.applyPeerSession(cachedSession)

                    val ruaTopic = callState.ruaDeriveTopic()
                    val ticket = callState.ticket
                    val senderID = callState.senderId

                    // Transition to RUA so currentTopic matches the topic we'll subscribe to.
                    callState.transitionToRua()

                    // Store callbacks
                    onReadyToCallCallback = onReadyToCall
                    protocolCompleteCallback = onProtocolComplete

                    val oob = OobController(
                        relayHost = Storage.getEffectiveRsHost(),
                        relayPort = Storage.getEffectiveRsPort(),
                        initialTopic = ruaTopic,
                        ticket = ticket,
                        senderID = senderID,
                        scope = serviceScope,
                        useTls = false,
                        heartbeatProvider = { callState.createHeartbeatMessage() }
                    )

                    oob.start { payload: ByteArray -> handleOobMessage(payload) }
                    oobController = oob

                    val ruaRequest = callState.ruaRequest()
                    oob.send(ruaRequest)
                    Log.d(TAG, "Sent RUA_REQUEST (${ruaRequest.size} bytes)")

                    // Wait for relay connection and message to be sent before placing call
                    // This ensures the recipient gets RUA_REQUEST via replay when they subscribe
                    oob.awaitConnected()

                    withContext(Dispatchers.Main) {
                        onReadyToCallCallback?.invoke()
                        onReadyToCallCallback = null
                    }

                    startProtocolTimeout()
                    return@launch
                }
                ruaOnlyMode = false
                
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
                    relayHost = Storage.getEffectiveRsHost(),
                    relayPort = Storage.getEffectiveRsPort(),
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
                
                // Wait for relay connection and message to be sent before placing call
                // This ensures the recipient gets AKE_REQUEST via replay when they subscribe
                oob.awaitConnected()
                
                // Signal that call can now be placed
                withContext(Dispatchers.Main) {
                    onReadyToCallCallback?.invoke()
                    onReadyToCallCallback = null
                }
                Log.d(TAG, "Call can now be placed, waiting for AKE_RESPONSE...")
                
                // Set timeout for protocol completion
                startProtocolTimeout()
                
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

                val peerKey = normalizePhone(callerNumber)
                currentPeerKey = peerKey
                val cacheEnabled = Storage.isPeerSessionCacheEnabled()
                val cachedSession = if (cacheEnabled) Storage.loadPeerSession(peerKey) else null

                // Bound metric to actual DIA protocol runtime (begin -> completion).
                MetricsRecorder.onIncomingDiaBegin(
                    call,
                    protocolEnabled = true,
                    cacheEnabled = cacheEnabled,
                    ruaOnlyMode = cachedSession != null
                )
                
                Log.d(TAG, "Caller: $callerNumber")
                
                // Create call state for incoming call
                var t0 = System.currentTimeMillis()
                val callState = CallState.create(config, callerNumber, outgoing = false)
                Log.d(TAG, "TIMING: CallState.create took ${System.currentTimeMillis() - t0}ms")
                currentCallState = callState

                resetSessionState()

                if (cachedSession != null) {
                    ruaOnlyMode = true
                    Log.d(TAG, "Using cached peer session ($peerKey) - running RUA-only")

                    t0 = System.currentTimeMillis()
                    callState.applyPeerSession(cachedSession)
                    Log.d(TAG, "TIMING: applyPeerSession took ${System.currentTimeMillis() - t0}ms")

                    t0 = System.currentTimeMillis()
                    val ruaTopic = callState.ruaDeriveTopic()
                    Log.d(TAG, "TIMING: ruaDeriveTopic took ${System.currentTimeMillis() - t0}ms")
                    
                    val ticket = callState.ticket
                    val senderID = callState.senderId

                    protocolCompleteCallback = onProtocolComplete

                    // Transition to RUA so currentTopic matches the topic we'll subscribe to.
                    t0 = System.currentTimeMillis()
                    callState.transitionToRua()
                    Log.d(TAG, "TIMING: transitionToRua took ${System.currentTimeMillis() - t0}ms")

                    // Initialize RUA state BEFORE connecting so we're ready to handle
                    // RUA_REQUEST as soon as it arrives via replay
                    t0 = System.currentTimeMillis()
                    callState.ruaInit()
                    Log.d(TAG, "TIMING: ruaInit took ${System.currentTimeMillis() - t0}ms")

                    val oob = OobController(
                        relayHost = Storage.getEffectiveRsHost(),
                        relayPort = Storage.getEffectiveRsPort(),
                        initialTopic = ruaTopic,
                        ticket = ticket,
                        senderID = senderID,
                        scope = serviceScope,
                        useTls = false,
                        heartbeatProvider = { callState.createHeartbeatMessage() }
                    )

                    t0 = System.currentTimeMillis()
                    oob.start { payload: ByteArray -> handleOobMessage(payload) }
                    oobController = oob

                    // Wait for relay connection before starting RUA timer
                    // (so we measure RUA protocol time, not connection setup)
                    oob.awaitConnected()
                    Log.d(TAG, "TIMING: oob.start+awaitConnected took ${System.currentTimeMillis() - t0}ms")

                    MetricsRecorder.onIncomingRuaBegin(call)
                    Log.d(TAG, "Subscribed to RUA topic, waiting for RUA_REQUEST...")

                    startProtocolTimeout()
                    return@launch
                }
                ruaOnlyMode = false
                
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
                    relayHost = Storage.getEffectiveRsHost(),
                    relayPort = Storage.getEffectiveRsPort(),
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
                
                // Wait for relay connection before starting AKE timer
                // (so AKE measures only protocol time, not connection setup)
                oob.awaitConnected()
                
                MetricsRecorder.onIncomingAkeBegin(call)
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
                    if (msgType == LibDia.MSG_BYE) {
                        Log.d(TAG, "Received BYE message - ending call")
                        endCallCleanup()
                        return@use
                    }

                    // Heartbeats are allowed on any topic; ignore them
                    if (msgType == LibDia.MSG_HEARTBEAT) {
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

                    // Shared ODA handling (role-agnostic).
                    // Return early so ODA messages do not enter caller/recipient routing.
                    when {
                        message.isOdaRequest -> {
                            handleOdaRequest(callState, payload)
                            return@use
                        }

                        message.isOdaResponse -> {
                            handleOdaResponse(callState, payload)
                            return@use
                        }
                    }
                    
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
        if (ruaOnlyMode) {
            when (msgType) {
                LibDia.MSG_RUA_RESPONSE -> handleCallerRuaResponse(callState, rawData)
                else -> Log.w(TAG, "Caller (RUA-only) received unexpected message type: $msgType")
            }
            return
        }

        when (msgType) {
            LibDia.MSG_AKE_RESPONSE -> handleCallerAkeResponse(callState, rawData)
            LibDia.MSG_RUA_RESPONSE -> handleCallerRuaResponse(callState, rawData)
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
            // (Matches dia sipcontroller ordering.)
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

            // Persist updated per-peer session state (if enabled)
            val peerKey = currentPeerKey
            if (peerKey != null && Storage.isPeerSessionCacheEnabled()) {
                try {
                    Storage.savePeerSession(peerKey, callState.exportPeerSession())
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to persist peer session: ${e.message}")
                }
            }
            
            // Get verified remote party
            val remoteParty = callState.remoteParty
            Log.d(TAG, "✓✓✓ PROTOCOL COMPLETE! Verified: ${remoteParty.name} (${remoteParty.phone})")
            
            // Cancel timeout
            timeoutJob?.cancel()
            timeoutJob = null
            
            // Start heartbeat now that protocol is complete
            oobController?.startHeartbeat()

            ruaComplete = true

            scheduleAutoOdaIfEnabled()
            
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
        if (ruaOnlyMode) {
            when (msgType) {
                LibDia.MSG_RUA_REQUEST -> handleRecipientRuaRequest(callState, rawData)
                else -> Log.w(TAG, "Recipient (RUA-only) received unexpected message type: $msgType")
            }
            return
        }

        when (msgType) {
            LibDia.MSG_AKE_REQUEST -> handleRecipientAkeRequest(callState, rawData)
            LibDia.MSG_AKE_COMPLETE -> handleRecipientAkeComplete(callState, rawData)
            LibDia.MSG_RUA_REQUEST -> handleRecipientRuaRequest(callState, rawData)
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
            CallManager.getPrimaryCall()?.let { MetricsRecorder.onIncomingAkeEnd(it) }
            Log.d(TAG, "✓ AKE Complete! Shared key established")
            
            // Derive RUA topic
            val ruaTopic = callState.ruaDeriveTopic()
            Log.d(TAG, "RUA topic derived: $ruaTopic")
            
            // Transition to RUA state
            CallManager.getPrimaryCall()?.let { MetricsRecorder.onIncomingRuaBegin(it) }
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

            CallManager.getPrimaryCall()?.let { MetricsRecorder.onIncomingRuaEnd(it) }

            // Persist updated per-peer session state (if enabled)
            val peerKey = currentPeerKey
            if (peerKey != null && Storage.isPeerSessionCacheEnabled()) {
                try {
                    Storage.savePeerSession(peerKey, callState.exportPeerSession())
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to persist peer session: ${e.message}")
                }
            }
            
            // Get verified remote party
            val remoteParty = callState.remoteParty
            Log.d(TAG, "✓✓✓ PROTOCOL COMPLETE! Verified: ${remoteParty.name} (${remoteParty.phone})")
            
            // Cancel timeout
            timeoutJob?.cancel()
            timeoutJob = null
            
            // Start heartbeat now that protocol is complete
            oobController?.startHeartbeat()

            ruaComplete = true

            scheduleAutoOdaIfEnabled()
            
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
     * Trigger an On-Demand Authentication (ODA) request from the local user.
     * ODA can occur multiple times during a call, but only one request may be in-flight at a time.
     */
    fun requestOnDemandAuthentication(
        attributes: List<String>,
        onResult: (OdaVerification) -> Unit,
        onError: (String) -> Unit = {},
        isAuto: Boolean = false
    ) {
        serviceScope.launch {
            val callState = currentCallState
            val oob = oobController
            if (callState == null || oob == null) {
                withContext(Dispatchers.Main) { onError("On-demand auth unavailable") }
                return@launch
            }

            if (!ruaComplete || !callState.isRuaActive) {
                withContext(Dispatchers.Main) { onError("On-demand auth not ready yet") }
                return@launch
            }

            if (!odaInFlight.compareAndSet(false, true)) {
                withContext(Dispatchers.Main) { onError("On-demand auth already in progress") }
                return@launch
            }

            odaInFlightIsAuto = isAuto

            odaResultCallback = onResult
            odaErrorCallback = onError

            odaTimeoutJob?.cancel()
            odaTimeoutJob = launch {
                delay(ODA_TIMEOUT_MS)
                if (odaInFlight.compareAndSet(true, false)) {
                    CallManager.getPrimaryCall()?.let { MetricsRecorder.onOdaCompleted(it, outcome = "oda_timeout", error = "oda timeout") }
                    CallManager.getPrimaryCall()?.let { MetricsRecorder.onIncomingOdaEnd(it, outcome = "oda_timeout", error = "oda timeout") }
                    val wasAuto = odaInFlightIsAuto
                    odaInFlightIsAuto = false
                    val cb = odaErrorCallback
                    clearOdaCallbacks()
                    hangupRingingCallAfterAutoOdaIfNeeded(wasAuto, reason = "oda_timeout")
                    withContext(Dispatchers.Main) { cb?.invoke("On-demand auth timed out") }
                }
            }

            try {
                CallManager.getPrimaryCall()?.let {
                    // ODA duration begins just before request creation (request creation is part of ODA).
                    MetricsRecorder.onOdaRequested(it)
                    MetricsRecorder.onIncomingOdaBegin(it, wasAuto = odaInFlightIsAuto)
                }

                val request = callState.odaRequest(attributes)
                oob.send(request)
                Log.d(TAG, "Sent ODA_REQUEST (${request.size} bytes) attrs=$attributes")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to send ODA request", e)
                odaTimeoutJob?.cancel()
                odaTimeoutJob = null
                odaInFlight.set(false)
                CallManager.getPrimaryCall()?.let {
                    MetricsRecorder.onOdaCompleted(it, outcome = "error", error = e.message ?: "oda request failed")
                    MetricsRecorder.onIncomingOdaEnd(it, outcome = "error", error = e.message ?: "oda request failed")
                }
                val wasAuto = odaInFlightIsAuto
                odaInFlightIsAuto = false
                val cb = odaErrorCallback
                clearOdaCallbacks()
                hangupRingingCallAfterAutoOdaIfNeeded(wasAuto, reason = "oda_request_error")
                withContext(Dispatchers.Main) { cb?.invoke(e.message ?: "Failed to start on-demand auth") }
            }
        }
    }

    private suspend fun handleOdaRequest(callState: CallState, rawData: ByteArray) {
        if (!ruaComplete || !callState.isRuaActive) {
            Log.w(TAG, "Ignoring ODA_REQUEST before RUA is complete")
            return
        }

        try {
            Log.d(TAG, "Handling ODA_REQUEST")
            val response = callState.odaResponse(rawData)
            oobController?.send(response)
            Log.d(TAG, "Sent ODA_RESPONSE (${response.size} bytes)")
        } catch (e: Exception) {
            Log.e(TAG, "Failed handling ODA_REQUEST", e)
        }
    }

    private suspend fun handleOdaResponse(callState: CallState, rawData: ByteArray) {
        if (!ruaComplete || !callState.isRuaActive) {
            Log.w(TAG, "Ignoring ODA_RESPONSE before RUA is complete")
            return
        }

        try {
            Log.d(TAG, "Handling ODA_RESPONSE")
            val verification = callState.odaVerify(rawData)
            Log.d(
                TAG,
                "ODA verification: verified=${verification.verified} issuer=${verification.issuer} credentialType=${verification.credentialType} disclosed=${verification.disclosedAttributes.keys}"
            )

            CallManager.getPrimaryCall()?.let { MetricsRecorder.onOdaCompleted(it, outcome = "oda_done") }
            CallManager.getPrimaryCall()?.let { MetricsRecorder.onIncomingOdaEnd(it, outcome = "oda_done") }

            odaTimeoutJob?.cancel()
            odaTimeoutJob = null
            odaInFlight.set(false)
            val wasAuto = odaInFlightIsAuto
            odaInFlightIsAuto = false
            val cb = odaResultCallback
            clearOdaCallbacks()

            hangupRingingCallAfterAutoOdaIfNeeded(wasAuto, reason = "oda_done")

            withContext(Dispatchers.Main) {
                cb?.invoke(verification)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed verifying ODA_RESPONSE", e)
            odaTimeoutJob?.cancel()
            odaTimeoutJob = null
            odaInFlight.set(false)
            CallManager.getPrimaryCall()?.let { MetricsRecorder.onOdaCompleted(it, outcome = "error", error = e.message ?: "oda verify failed") }
            CallManager.getPrimaryCall()?.let { MetricsRecorder.onIncomingOdaEnd(it, outcome = "error", error = e.message ?: "oda verify failed") }
            val wasAuto = odaInFlightIsAuto
            odaInFlightIsAuto = false
            val cb = odaErrorCallback
            clearOdaCallbacks()

            hangupRingingCallAfterAutoOdaIfNeeded(wasAuto, reason = "oda_verify_error")

            withContext(Dispatchers.Main) {
                cb?.invoke(e.message ?: "On-demand auth verification failed")
            }
        }
    }

    private fun hangupRingingCallAfterAutoOdaIfNeeded(wasAuto: Boolean, reason: String) {
        if (!wasAuto) return
        if (!Storage.isAutoOdaEnabled()) return

        if (CallManager.getState() == Call.STATE_RINGING) {
            Log.i(TAG, "Auto ODA completed ($reason) - hanging up ringing call")
            CallManager.reject()
        }
    }

    private fun resetSessionState() {
        ruaComplete = false
        ruaOnlyMode = false
        odaInFlight.set(false)
        odaInFlightIsAuto = false
        autoOdaScheduledJob?.cancel()
        autoOdaScheduledJob = null
        odaTimeoutJob?.cancel()
        odaTimeoutJob = null
        clearOdaCallbacks()
    }

    private fun scheduleAutoOdaIfEnabled() {
        if (!Storage.isAutoOdaEnabled()) {
            return
        }

        // Best-effort only; never affect core call/auth behavior.
        autoOdaScheduledJob?.cancel()
        val call = CallManager.getPrimaryCall() ?: return

        MetricsRecorder.onIncomingAutoOdaPlanned(call, enabled = true, delayMs = AUTO_ODA_DELAY_MS)

        autoOdaScheduledJob = serviceScope.launch {
            delay(AUTO_ODA_DELAY_MS)

            val attrs = listOf("name", "issuer")
            requestOnDemandAuthentication(
                attributes = attrs,
                isAuto = true,
                onResult = { _ ->
                    // No UI for auto mode.
                },
                onError = { msg ->
                    Log.w(TAG, "Auto ODA failed: $msg")
                }
            )
        }
    }

    private fun clearOdaCallbacks() {
        odaResultCallback = null
        odaErrorCallback = null
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

            odaTimeoutJob?.cancel()
            odaTimeoutJob = null
            odaInFlight.set(false)
            clearOdaCallbacks()
            ruaComplete = false
            ruaOnlyMode = false
            currentPeerKey = null

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

            odaTimeoutJob?.cancel()
            odaTimeoutJob = null
            odaInFlight.set(false)
            clearOdaCallbacks()
            ruaComplete = false
            ruaOnlyMode = false
            currentPeerKey = null
            
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

    private fun normalizePhone(phone: String): String = phone.filter { it.isDigit() }
}
