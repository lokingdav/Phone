package org.fossify.phone.callerauth.protocol

import denseid.protocol.v1.Protocol
import org.fossify.phone.callerauth.DoubleRatchet
import org.fossify.phone.callerauth.Utilities

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
     */
    fun startAsCallerAke(): Protocol.AkeMessage {
        Ake.initAke(callState)
        val message = Ake.akeRequest(callState)
        currentPhase = Phase.AKE_INITIATED
        android.util.Log.d(tag, "Caller: AKE request created")
        return message
    }
    
    /**
     * Step 2 (Caller): Process AKE response from recipient and complete AKE.
     */
    fun callerProcessAkeResponse(response: Protocol.AkeMessage): Boolean {
        if (currentPhase != Phase.AKE_INITIATED) {
            lastError = "Invalid phase for processing AKE response: $currentPhase"
            currentPhase = Phase.ERROR
            return false
        }
        
        val success = Ake.akeComplete(callState, response, callState.dst)
        if (success) {
            currentPhase = Phase.AKE_COMPLETE
            android.util.Log.d(tag, "Caller: AKE complete")
        } else {
            lastError = "AKE response verification failed"
            currentPhase = Phase.ERROR
        }
        return success
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
     * @param request The incoming AKE request
     * @param callerPhoneNumber The caller's phone number from caller ID
     */
    fun recipientProcessAkeRequest(
        request: Protocol.AkeMessage,
        callerPhoneNumber: String
    ): Protocol.AkeMessage? {
        Ake.initAke(callState)
        
        val response = Ake.akeResponse(callState, request, callerPhoneNumber)
        if (response != null) {
            // Store caller's DH public key for finalization
            val callerDhPk = request.dhPk.toByteArray()
            
            // Finalize AKE on recipient side
            if (Ake.akeFinalize(callState, callerDhPk)) {
                currentPhase = Phase.AKE_COMPLETE
                android.util.Log.d(tag, "Recipient: AKE response created and finalized")
            } else {
                lastError = "AKE finalization failed"
                currentPhase = Phase.ERROR
                return null
            }
        } else {
            lastError = "AKE request verification failed"
            currentPhase = Phase.ERROR
        }
        
        return response
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
