package org.fossify.phone.callerauth.protocol

import denseid.protocol.v1.Protocol

/**
 * High-level protocol handler that orchestrates AKE and RUA flows.
 * 
 * This class provides a simple interface for caller authentication,
 * managing state transitions and message handling internally.
 */
class ProtocolHandler(
    private val callState: CallState
) {
    private val tag = "ProtocolHandler"
    
    /**
     * Protocol phases
     */
    enum class Phase {
        IDLE,
        AKE_INITIATED,
        AKE_WAITING_COMPLETE,  // Recipient waiting for AkeComplete
        AKE_RESPONDED,
        AKE_COMPLETE,
        RUA_INITIATED,
        RUA_RESPONDED,
        RUA_COMPLETE,
        SECURE_CHANNEL_ESTABLISHED,
        ERROR
    }
    
    var currentPhase: Phase = Phase.IDLE
        private set
    
    var lastError: String? = null
        private set
    
    // === CALLER (Outgoing call) FLOW ===
    
    /**
     * Step 1 (Caller): Initialize and create AKE request.
     * Returns serialized ProtocolMessage bytes (unencrypted).
     */
    fun startAsCallerAke(): ByteArray {
        Ake.initAke(callState)
        val message = Ake.akeRequest(callState)
        currentPhase = Phase.AKE_INITIATED
        android.util.Log.d(tag, "Caller: AKE request created")
        return message
    }
    
    /**
     * Step 2 (Caller): Process AKE response from recipient and complete AKE.
     * Returns AkeComplete message bytes (PKE encrypted to recipient) to send to recipient.
     */
    fun callerProcessAkeResponse(responseProtocolMsg: Protocol.ProtocolMessage): ByteArray? {
        if (currentPhase != Phase.AKE_INITIATED) {
            lastError = "Invalid phase for processing AKE response: $currentPhase"
            currentPhase = Phase.ERROR
            return null
        }
        
        val completeMessage = Ake.akeComplete(callState, responseProtocolMsg, callState.dst)
        if (completeMessage != null) {
            currentPhase = Phase.AKE_COMPLETE
            android.util.Log.d(tag, "Caller: AKE complete")
        } else {
            lastError = "AKE response verification failed"
            currentPhase = Phase.ERROR
        }
        return completeMessage
    }
    
    /**
     * Step 3 (Caller): Create RUA request with call reason.
     */
    fun callerCreateRuaRequest(reason: String): Protocol.RuaMessage? {
        if (currentPhase != Phase.AKE_COMPLETE) {
            throw IllegalStateException("AKE must be complete before starting RUA")
        }
        
        Rua.initRua(callState)
        val message = Rua.ruaRequest(callState, reason)
        if (message != null) {
            currentPhase = Phase.RUA_INITIATED
            android.util.Log.d(tag, "Caller: RUA request created with reason: $reason")
        }
        return message
    }
    
    /**
     * Step 4 (Caller): Process RUA response and complete protocol.
     */
    fun callerProcessRuaResponse(response: Protocol.RuaMessage): Boolean {
        if (currentPhase != Phase.RUA_INITIATED) {
            lastError = "Invalid phase for processing RUA response: $currentPhase"
            currentPhase = Phase.ERROR
            return false
        }
        
        val success = Rua.ruaFinalize(callState, response)
        if (success) {
            currentPhase = Phase.SECURE_CHANNEL_ESTABLISHED
            android.util.Log.d(tag, "Caller: Protocol complete, secure channel established")
        } else {
            lastError = "RUA response verification failed"
            currentPhase = Phase.ERROR
        }
        return success
    }
    
    // === RECIPIENT (Incoming call) FLOW ===
    
    /**
     * Step 1 (Recipient): Process incoming AKE request and create response.
     * 
     * Note: In the new protocol, AKE request doesn't contain DhPk.
     * The recipient will finalize AKE when receiving AkeComplete message.
     * 
     * @param requestProtocolMsg The incoming ProtocolMessage containing AKE request
     * @param callerPhoneNumber The caller's phone number from caller ID
     * @return Serialized ProtocolMessage bytes (PKE encrypted to caller), or null if verification fails
     */
    fun recipientProcessAkeRequest(
        requestProtocolMsg: Protocol.ProtocolMessage,
        callerPhoneNumber: String
    ): ByteArray? {
        Ake.initAke(callState)
        
        val response = Ake.akeResponse(callState, requestProtocolMsg, callerPhoneNumber)
        if (response != null) {
            currentPhase = Phase.AKE_WAITING_COMPLETE
            android.util.Log.d(tag, "Recipient: AKE response created, waiting for AkeComplete")
        } else {
            lastError = "AKE request verification failed"
            currentPhase = Phase.ERROR
        }
        
        return response
    }
    
    /**
     * Step 1.5 (Recipient): Process incoming AKE complete message and finalize AKE.
     * 
     * @param completeProtocolMsg The AkeComplete ProtocolMessage (PKE encrypted)
     */
    fun recipientProcessAkeComplete(completeProtocolMsg: Protocol.ProtocolMessage): Boolean {
        if (currentPhase != Phase.AKE_WAITING_COMPLETE) {
            lastError = "Invalid phase for processing AKE complete: $currentPhase"
            currentPhase = Phase.ERROR
            return false
        }
        
        val success = Ake.akeFinalize(callState, completeProtocolMsg)
        if (success) {
            currentPhase = Phase.AKE_COMPLETE
            android.util.Log.d(tag, "Recipient: AKE finalized")
        } else {
            lastError = "AKE finalization failed"
            currentPhase = Phase.ERROR
        }
        return success
    }
    
    /**
     * Step 2 (Recipient): Process incoming RUA request and create response.
     */
    fun recipientProcessRuaRequest(request: Protocol.RuaMessage): Protocol.RuaMessage? {
        if (currentPhase != Phase.AKE_COMPLETE) {
            lastError = "AKE must be complete before processing RUA"
            currentPhase = Phase.ERROR
            return null
        }
        
        Rua.initRua(callState)
        
        val response = Rua.ruaResponse(callState, request)
        if (response != null) {
            currentPhase = Phase.SECURE_CHANNEL_ESTABLISHED
            android.util.Log.d(tag, "Recipient: RUA response created, secure channel established")
        } else {
            lastError = "RUA request verification failed"
            currentPhase = Phase.ERROR
        }
        
        return response
    }
    
    // === SECURE MESSAGING ===
    
    /**
     * Encrypts a message using the established Double Ratchet session.
     */
    fun encryptMessage(plaintext: ByteArray): Protocol.DrMessage? {
        if (currentPhase != Phase.SECURE_CHANNEL_ESTABLISHED) {
            android.util.Log.e(tag, "Cannot encrypt: secure channel not established")
            return null
        }
        
        val drSession = callState.drSession
        if (drSession == null) {
            android.util.Log.e(tag, "DR session not initialized")
            return null
        }
        
        // Associated data includes the current topic
        val associatedData = callState.getCurrentTopic().toByteArray()
        
        return DoubleRatchet.encrypt(drSession, plaintext, associatedData)
    }
    
    /**
     * Decrypts a message using the established Double Ratchet session.
     */
    fun decryptMessage(message: Protocol.DrMessage): ByteArray? {
        if (currentPhase != Phase.SECURE_CHANNEL_ESTABLISHED) {
            android.util.Log.e(tag, "Cannot decrypt: secure channel not established")
            return null
        }
        
        val drSession = callState.drSession
        if (drSession == null) {
            android.util.Log.e(tag, "DR session not initialized")
            return null
        }
        
        val associatedData = callState.getCurrentTopic().toByteArray()
        
        return try {
            DoubleRatchet.decrypt(drSession, message, associatedData)
        } catch (e: Exception) {
            android.util.Log.e(tag, "Decryption failed: ${e.message}")
            null
        }
    }
    
    // === STATUS ACCESSORS ===
    
    /**
     * Returns true if the secure channel is established.
     */
    fun isSecureChannelEstablished(): Boolean = 
        currentPhase == Phase.SECURE_CHANNEL_ESTABLISHED
    
    /**
     * Gets the verified caller info.
     */
    fun getVerifiedCallerInfo(): Ake.CallerInfo? = Ake.getVerifiedCallerInfo(callState)
    
    /**
     * Gets the counterpart's RTU info (display name, etc).
     */
    fun getCounterpartRtu(): Rua.RtuInfo? = Rua.getCounterpartRtu(callState)
    
    /**
     * Gets the current topic for message routing.
     */
    fun getCurrentTopic(): String = callState.getCurrentTopic()
    
    /**
     * Gets the AKE topic for message routing during AKE phase.
     */
    fun getAkeTopic(): String = callState.getAkeTopic()
}
