package org.fossify.phone.callerauth.protocol

import denseid.protocol.v1.Protocol
import io.github.lokingdav.libdia.LibDia
import org.fossify.phone.callerauth.DoubleRatchet
import org.fossify.phone.callerauth.Utilities

/**
 * Authenticated Key Exchange (AKE) protocol implementation.
 * 
 * This implements the AKE protocol from Go's denseid/internal/protocol/ake.go.
 * The protocol establishes a shared secret between two parties and initializes
 * a Double Ratchet session for subsequent encrypted communication.
 * 
 * Protocol Flow (matches Go exactly):
 * 1. Caller: initAke() -> akeRequest() returns ByteArray (unencrypted ProtocolMessage)
 * 2. Recipient: initAke() -> akeResponse(protocolMsg) returns ByteArray (PKE encrypted to caller)
 * 3. Caller: akeComplete(protocolMsg) returns ByteArray (PKE encrypted to recipient)
 * 4. Recipient: akeFinalize(protocolMsg) -> completes AKE
 * 
 * Encryption:
 * - AkeRequest: Payload is NOT encrypted (recipient needs caller's public keys)
 * - AkeResponse: Payload is PKE encrypted to caller's PkePk
 * - AkeComplete: Payload is PKE encrypted to recipient's PkePk
 */
object Ake {
    private const val TAG = "Ake"
    
    /**
     * Initializes AKE state for a new call.
     * Generates ephemeral DH keypair using LibDia and stores in call state.
     * Matches Go: dia.DHKeygen()
     */
    fun initAke(callState: CallState) {
        // Use LibDia for DH keygen (matches Go: dia.DHKeygen())
        val (dhSk, dhPk) = LibDia.dhKeygen()
        
        // Compute AKE topic: HashAll(Src, Ts) as byte arrays
        // Matches Go: helpers.HashAll([]byte(callState.Src), []byte(callState.Ts))
        val akeTopic = Utilities.hashAll(
            callState.src.toByteArray(Charsets.UTF_8),
            callState.ts.toByteArray(Charsets.UTF_8)
        )
        
        callState.initAke(dhSk, dhPk, akeTopic)
        android.util.Log.d(TAG, "Initialized AKE with DhPk: ${Utilities.encodeToHex(dhPk).take(16)}...")
    }
    
    /**
     * Creates an AKE request message (caller side).
     * 
     * Go equivalent: AkeRequest(caller *CallState) ([]byte, error)
     * 
     * Note: AkeRequest does NOT include DhPk - it only sends ZK proof and public keys.
     * The DhPk is sent later in AkeComplete.
     * AkeRequest is NOT encrypted (recipient needs to see caller's public keys).
     * 
     * @param callState The call state containing subscriber config and AKE state
     * @return Serialized ProtocolMessage bytes to send to recipient
     */
    fun akeRequest(callState: CallState): ByteArray {
        val config = callState.config
        
        // Compute challenge: HashAll(topic)
        // Matches Go: challenge := helpers.HashAll(caller.Ake.Topic)
        val challenge = Utilities.hashAll(callState.ake.topic)
        
        // Create ZK proof of identity
        val proof = ZkProofs.createProofFromConfig(config, challenge)
        
        // Store challenge and proof for later verification
        // Matches Go: caller.UpdateCaller(challenge, proof)
        callState.updateCaller(challenge, proof)
        
        // Build the AKE message - NO DhPk in AkeRequest!
        // Matches Go: AkeMessage{AmfPk, PkePk, DrPk, Expiration, Proof}
        val akeMessage = Protocol.AkeMessage.newBuilder()
            .setAmfPk(com.google.protobuf.ByteString.copyFrom(config.amfPublicKey))
            .setPkePk(com.google.protobuf.ByteString.copyFrom(config.pkePublicKey))
            .setDrPk(com.google.protobuf.ByteString.copyFrom(config.drPublicKey))
            .setExpiration(com.google.protobuf.ByteString.copyFrom(config.enExpiration))
            .setProof(com.google.protobuf.ByteString.copyFrom(proof))
            .build()
        
        // Send on AKE topic (NOT encrypted - recipient needs to see caller's public keys)
        // Matches Go: CreateAkeMessage(caller.SenderId, caller.GetAkeTopic(), TypeAkeRequest, akeMsg, nil)
        val msg = ProtocolMessages.createAkeMessage(
            senderId = callState.senderId,
            topic = callState.getAkeTopic(),
            msgType = Protocol.MessageType.AKE_REQUEST,
            payload = akeMessage,
            recipientPkePk = null  // NOT encrypted
        )
        
        android.util.Log.d(TAG, "Created AKE request for ${config.myPhone}")
        return msg
    }
    
    /**
     * Processes an incoming AKE request and creates a response (recipient side).
     * 
     * Go equivalent: AkeResponse(recipient *CallState, callerMsg *ProtocolMessage) ([]byte, error)
     * 
     * @param callState The call state containing subscriber config and AKE state
     * @param incomingProtocolMsg The received ProtocolMessage from caller
     * @param callerPhoneNumber The caller's phone number (for ZK proof verification)
     * @return Serialized ProtocolMessage bytes (PKE encrypted to caller), or null if verification fails
     */
    fun akeResponse(
        callState: CallState,
        incomingProtocolMsg: Protocol.ProtocolMessage,
        callerPhoneNumber: String
    ): ByteArray? {
        val config = callState.config
        
        // Decode the AKE message (AkeRequest is NOT encrypted)
        // Matches Go: DecodeAkePayload(callerMsg, nil)
        val caller = try {
            ProtocolMessages.decodeAkePayload(incomingProtocolMsg, null)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to decode AKE request: ${e.message}")
            return null
        }
        
        // Compute challenge0: HashAll(topic)
        // Matches Go: challenge0 := helpers.HashAll(recipient.Ake.Topic)
        val challenge0 = Utilities.hashAll(callState.ake.topic)
        
        // Verify the incoming proof
        // Matches Go: VerifyZKProof(caller, recipient.Src, challenge0, recipient.Config.RaPublicKey)
        if (!ZkProofs.verifyProofFromMessage(
            caller,
            challenge0,
            callerPhoneNumber,
            config.raPublicKey
        )) {
            android.util.Log.e(TAG, "AKE request proof verification failed")
            return null
        }
        
        // Compute challenge1 for our proof: HashAll(callerProof, recipientDhPk, challenge0)
        // Matches Go: challenge1 := helpers.HashAll(caller.GetProof(), recipient.Ake.DhPk, challenge0)
        val callerProof = caller.proof.toByteArray()
        val challenge1 = Utilities.hashAll(callerProof, callState.ake.dhPk, challenge0)
        
        // Create our ZK proof with challenge1
        val proof = ZkProofs.createProofFromConfig(config, challenge1)
        
        // Store state for AkeFinalize
        // Matches Go: recipient.Ake.CallerProof, recipient.Ake.RecipientProof, recipient.Counterpart*
        callState.ake.callerProof = callerProof
        callState.ake.recipientProof = proof
        callState.counterpartAmfPk = caller.amfPk.toByteArray()
        callState.counterpartPkePk = caller.pkePk.toByteArray()
        callState.counterpartDrPk = caller.drPk.toByteArray()
        
        // Build response message - includes DhPk
        // Matches Go: AkeMessage{DhPk, AmfPk, PkePk, DrPk, Expiration, Proof}
        val responseMessage = Protocol.AkeMessage.newBuilder()
            .setDhPk(com.google.protobuf.ByteString.copyFrom(callState.ake.dhPk))
            .setAmfPk(com.google.protobuf.ByteString.copyFrom(config.amfPublicKey))
            .setPkePk(com.google.protobuf.ByteString.copyFrom(config.pkePublicKey))
            .setDrPk(com.google.protobuf.ByteString.copyFrom(config.drPublicKey))
            .setExpiration(com.google.protobuf.ByteString.copyFrom(config.enExpiration))
            .setProof(com.google.protobuf.ByteString.copyFrom(proof))
            .build()
        
        // Respond on AKE topic (payload encrypted with caller's PKE public key)
        // Matches Go: CreateAkeMessage(recipient.SenderId, recipient.GetAkeTopic(), TypeAkeResponse, akeMsg, caller.GetPkePk())
        val msg = ProtocolMessages.createAkeMessage(
            senderId = callState.senderId,
            topic = callState.getAkeTopic(),
            msgType = Protocol.MessageType.AKE_RESPONSE,
            payload = responseMessage,
            recipientPkePk = caller.pkePk.toByteArray()  // Encrypt to caller's PKE public key
        )
        
        android.util.Log.d(TAG, "Created AKE response for $callerPhoneNumber")
        return msg
    }
    
    /**
     * Completes AKE on the caller side after receiving response.
     * Computes shared key and initializes Double Ratchet session.
     * 
     * Go equivalent: AkeComplete(caller *CallState, recipientMsg *ProtocolMessage) ([]byte, error)
     * 
     * @param callState The call state
     * @param responseProtocolMsg The AKE response ProtocolMessage from recipient (PKE encrypted)
     * @param recipientPhoneNumber The recipient's phone number
     * @return Serialized ProtocolMessage bytes (PKE encrypted to recipient), or null if verification fails
     */
    fun akeComplete(
        callState: CallState,
        responseProtocolMsg: Protocol.ProtocolMessage,
        recipientPhoneNumber: String
    ): ByteArray? {
        val config = callState.config
        
        // Decode the AKE message (decrypt with caller's PKE private key)
        // Matches Go: DecodeAkePayload(recipientMsg, caller.Config.PkePrivateKey)
        val recipient = try {
            ProtocolMessages.decodeAkePayload(responseProtocolMsg, config.pkePrivateKey)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to decode AKE response: ${e.message}")
            return null
        }
        
        val recipientDhPk = recipient.dhPk.toByteArray()
        val recipientProof = recipient.proof.toByteArray()
        
        if (recipientDhPk.isEmpty() || recipientProof.isEmpty()) {
            android.util.Log.e(TAG, "Missing DhPk or Proof in AkeResponse")
            return null
        }
        
        // Compute challenge: HashAll(callerProof, recipientDhPk, chal0)
        // Matches Go: challenge := helpers.HashAll(caller.Ake.CallerProof, recipientDhPk, caller.Ake.Chal0)
        val challenge = Utilities.hashAll(
            callState.ake.callerProof,
            recipientDhPk,
            callState.ake.chal0
        )
        
        // Verify the response proof
        // Matches Go: VerifyZKProof(recipient, caller.Dst, challenge, caller.Config.RaPublicKey)
        if (!ZkProofs.verifyProofFromMessage(
            recipient,
            challenge,
            recipientPhoneNumber,
            config.raPublicKey
        )) {
            android.util.Log.e(TAG, "AKE response proof verification failed")
            return null
        }
        
        // Store peer's keys
        callState.counterpartAmfPk = recipient.amfPk.toByteArray()
        callState.counterpartPkePk = recipient.pkePk.toByteArray()
        callState.counterpartDrPk = recipient.drPk.toByteArray()
        
        // Compute DH secret using LibDia
        // Matches Go: secret, err := dia.DHComputeSecret(caller.Ake.DhSk, recipientDhPk)
        val secret = LibDia.dhComputeSecret(callState.ake.dhSk, recipientDhPk)
        
        // Compute shared key: HashAll(topic, callerProof, recipientProof, callerDhPk, recipientDhPk, secret)
        // Matches Go: ComputeSharedKey(caller.Ake.Topic, caller.Ake.CallerProof, recipientProof, caller.Ake.DhPk, recipientDhPk, secret)
        val sharedKey = computeSharedKey(
            callState.ake.topic,
            callState.ake.callerProof,
            recipientProof,
            callState.ake.dhPk,
            recipientDhPk,
            secret
        )
        
        callState.setSharedKey(sharedKey)
        
        // Initialize Double Ratchet as caller
        // Matches Go: InitDrSessionAsCaller(caller.Ake.Topic, caller.SharedKey, caller.CounterpartDrPk)
        val drSession = DoubleRatchet.initAsCaller(
            sessionId = callState.ake.topic,
            sharedKey = sharedKey,
            remoteDrPk = callState.counterpartDrPk
        )
        callState.drSession = drSession
        
        // Build AkeComplete message with both DhPks concatenated
        // Matches Go: AkeMessage{DhPk: helpers.ConcatBytes(caller.Ake.DhPk, recipientDhPk)}
        val combinedDhPk = Utilities.concatBytes(callState.ake.dhPk, recipientDhPk)
        val completeMessage = Protocol.AkeMessage.newBuilder()
            .setDhPk(com.google.protobuf.ByteString.copyFrom(combinedDhPk))
            .build()
        
        // Send on AKE topic (payload encrypted with recipient's PKE public key)
        // Matches Go: CreateAkeMessage(caller.SenderId, caller.GetAkeTopic(), TypeAkeComplete, akeMsg, recipient.GetPkePk())
        val msg = ProtocolMessages.createAkeMessage(
            senderId = callState.senderId,
            topic = callState.getAkeTopic(),
            msgType = Protocol.MessageType.AKE_COMPLETE,
            payload = completeMessage,
            recipientPkePk = recipient.pkePk.toByteArray()  // Encrypt to recipient's PKE public key
        )
        
        android.util.Log.d(TAG, "AKE completed as caller, shared key: ${Utilities.encodeToHex(sharedKey).take(16)}...")
        return msg
    }
    
    /**
     * Finalizes AKE on the recipient side.
     * Computes shared key and initializes Double Ratchet session.
     * 
     * Go equivalent: AkeFinalize(recipient *CallState, callerMsg *ProtocolMessage) error
     * 
     * @param callState The call state with peer keys already stored from akeResponse
     * @param completeProtocolMsg The AkeComplete ProtocolMessage (PKE encrypted)
     * @return true if successful, false if verification fails
     */
    fun akeFinalize(callState: CallState, completeProtocolMsg: Protocol.ProtocolMessage): Boolean {
        val config = callState.config
        
        // Decode the AKE message (decrypt with recipient's PKE private key)
        // Matches Go: DecodeAkePayload(callerMsg, recipient.Config.PkePrivateKey)
        val caller = try {
            ProtocolMessages.decodeAkePayload(completeProtocolMsg, config.pkePrivateKey)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to decode AKE complete: ${e.message}")
            return false
        }
        
        val combinedDhPk = caller.dhPk.toByteArray()
        
        // Validate DhPk length (must be 64 bytes = 2 x 32-byte keys)
        // Matches Go: if len(dhPk) < 64 { return error }
        if (combinedDhPk.size < 64) {
            android.util.Log.e(TAG, "Invalid DhPk length: ${combinedDhPk.size}")
            return false
        }
        
        // Extract caller's DhPk (first 32 bytes) and recipient's DhPk (last 32 bytes)
        val callerDhPk = combinedDhPk.copyOfRange(0, 32)
        val recipientDhPk = combinedDhPk.copyOfRange(32, 64)
        
        // Verify recipient's DhPk matches our own
        // Matches Go: if !bytes.Equal(dhPk[32:], recipient.Ake.DhPk) { return error }
        if (!recipientDhPk.contentEquals(callState.ake.dhPk)) {
            android.util.Log.e(TAG, "Recipient DH PK do not match")
            return false
        }
        
        // Compute DH secret using LibDia
        // Matches Go: secret, err := dia.DHComputeSecret(recipient.Ake.DhSk, dhPk[:32])
        val secret = LibDia.dhComputeSecret(callState.ake.dhSk, callerDhPk)
        
        // Compute shared key: HashAll(topic, callerProof, recipientProof, callerDhPk, recipientDhPk, secret)
        // Matches Go: ComputeSharedKey(recipient.Ake.Topic, recipient.Ake.CallerProof, recipient.Ake.RecipientProof, dhPk[:32], recipient.Ake.DhPk, secret)
        val sharedKey = computeSharedKey(
            callState.ake.topic,
            callState.ake.callerProof,
            callState.ake.recipientProof,
            callerDhPk,
            callState.ake.dhPk,
            secret
        )
        
        callState.setSharedKey(sharedKey)
        
        // Initialize Double Ratchet as recipient
        // Matches Go: InitDrSessionAsRecipient(recipient.Ake.Topic, recipient.SharedKey, recipient.Config.DrPrivateKey, recipient.Config.DrPublicKey)
        val drSession = DoubleRatchet.initAsRecipient(
            sessionId = callState.ake.topic,
            sharedKey = sharedKey,
            drPrivateKey = config.drPrivateKey,
            drPublicKey = config.drPublicKey
        )
        callState.drSession = drSession
        
        android.util.Log.d(TAG, "AKE finalized as recipient, shared key: ${Utilities.encodeToHex(sharedKey).take(16)}...")
        return true
    }
    
    /**
     * Computes shared key using HashAll.
     * 
     * Matches Go: func ComputeSharedKey(tpc, pieA, pieB, A, B, sec []byte) []byte {
     *     return helpers.HashAll(tpc, pieA, pieB, A, B, sec)
     * }
     * 
     * @param tpc AKE topic
     * @param pieA Caller's ZK proof
     * @param pieB Recipient's ZK proof
     * @param A Caller's DH public key
     * @param B Recipient's DH public key
     * @param sec DH shared secret
     * @return 32-byte shared key
     */
    private fun computeSharedKey(
        tpc: ByteArray,
        pieA: ByteArray,
        pieB: ByteArray,
        A: ByteArray,
        B: ByteArray,
        sec: ByteArray
    ): ByteArray {
        return Utilities.hashAll(tpc, pieA, pieB, A, B, sec)
    }
    
    /**
     * Gets the verified caller information after AKE completes.
     * 
     * @param callState The completed call state
     * @return CallerInfo with phone number, or null if not available
     */
    fun getVerifiedCallerInfo(callState: CallState): CallerInfo? {
        if (callState.sharedKey.isEmpty()) return null
        
        return CallerInfo(
            phoneNumber = callState.src,
            verified = true
        )
    }
    
    /**
     * Verified caller information.
     */
    data class CallerInfo(
        val phoneNumber: String,
        val verified: Boolean
    )
}
