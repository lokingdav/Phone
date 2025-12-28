package org.fossify.phone.callerauth.protocol

import denseid.protocol.v1.Protocol
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.fossify.phone.callerauth.DoubleRatchet
import org.fossify.phone.callerauth.Utilities
import java.security.SecureRandom
import org.bouncycastle.crypto.digests.SHA256Digest

/**
 * Authenticated Key Exchange (AKE) protocol implementation.
 * 
 * This implements the AKE protocol from Go's denseid/internal/protocol/ake.go.
 * The protocol establishes a shared secret between two parties and initializes
 * a Double Ratchet session for subsequent encrypted communication.
 * 
 * Protocol Flow:
 * 1. Caller: initAke() -> akeRequest() -> sends AkeMessage to recipient
 * 2. Recipient: initAke() -> akeResponse() -> sends AkeMessage back to caller
 * 3. Caller: akeComplete() -> computes shared key, inits DR as caller
 * 4. Recipient: akeFinalize() -> computes shared key, inits DR as recipient
 */
object Ake {
    private const val TAG = "Ake"
    
    // AKE info strings for HKDF key derivation (must match Go implementation)
    private const val AKE_SHARED_KEY_INFO = "ake-shared-key"
    private const val AKE_DR_KEY_INFO = "ake-dr-key"
    
    // Key sizes
    private const val X25519_KEY_SIZE = 32
    private const val SHARED_KEY_SIZE = 32
    
    /**
     * Generates a new ephemeral X25519 keypair for AKE.
     */
    fun generateEphemeralKeyPair(): Pair<ByteArray, ByteArray> {
        val random = SecureRandom()
        val privateKey = X25519PrivateKeyParameters(random)
        val publicKey = privateKey.generatePublicKey()
        return Pair(privateKey.encoded, publicKey.encoded)
    }
    
    /**
     * Initializes AKE state for a new call.
     * Generates ephemeral DH keypair and stores in call state.
     */
    fun initAke(callState: CallState) {
        val (privateKey, publicKey) = generateEphemeralKeyPair()
        val topic = Utilities.hash(callState.getAkeLabel())
        callState.initAke(privateKey, publicKey, topic)
        android.util.Log.d(TAG, "Initialized AKE with ephemeral public key: ${Utilities.encodeToHex(publicKey).take(16)}...")
    }
    
    /**
     * Creates an AKE request message (caller side).
     * 
     * @param callState The call state containing subscriber config and AKE state
     * @return AkeMessage protobuf to send to recipient
     */
    fun akeRequest(callState: CallState): Protocol.AkeMessage {
        val config = callState.config
        val nonce = callState.ake.topic
        
        // Create ZK proof of identity
        val proof = ZkProofs.createProofFromConfig(config, nonce)
        
        // Build the AKE message (following proto definition)
        val akeMessage = Protocol.AkeMessage.newBuilder()
            .setDhPk(com.google.protobuf.ByteString.copyFrom(callState.ake.dhPk))
            .setAmfPk(com.google.protobuf.ByteString.copyFrom(config.amfPublicKey))
            .setExpiration(com.google.protobuf.ByteString.copyFrom(config.enExpiration))
            .setProof(com.google.protobuf.ByteString.copyFrom(proof))
            .setPkePk(com.google.protobuf.ByteString.copyFrom(config.pkePublicKey))
            .setDrPk(com.google.protobuf.ByteString.copyFrom(config.drPublicKey))
            .build()
        
        android.util.Log.d(TAG, "Created AKE request for ${config.myPhone}")
        return akeMessage
    }
    
    /**
     * Processes an incoming AKE request and creates a response (recipient side).
     * 
     * @param callState The call state containing subscriber config and AKE state
     * @param incomingMessage The received AKE request from caller
     * @param callerPhoneNumber The caller's phone number (from caller ID)
     * @return AkeMessage protobuf to send back to caller, or null if verification fails
     */
    fun akeResponse(
        callState: CallState,
        incomingMessage: Protocol.AkeMessage,
        callerPhoneNumber: String
    ): Protocol.AkeMessage? {
        val config = callState.config
        val nonce = callState.ake.topic
        
        // Verify the incoming proof
        if (!ZkProofs.verifyProofFromMessage(
            incomingMessage,
            nonce,
            callerPhoneNumber,
            config.raPublicKey
        )) {
            android.util.Log.e(TAG, "AKE request proof verification failed")
            return null
        }
        
        // Store peer's public keys
        callState.counterpartAmfPk = incomingMessage.amfPk.toByteArray()
        callState.counterpartPkePk = incomingMessage.pkePk.toByteArray()
        callState.counterpartDrPk = incomingMessage.drPk.toByteArray()
        
        // Create our ZK proof
        val proof = ZkProofs.createProofFromConfig(config, nonce)
        
        // Build response message
        val responseMessage = Protocol.AkeMessage.newBuilder()
            .setDhPk(com.google.protobuf.ByteString.copyFrom(callState.ake.dhPk))
            .setAmfPk(com.google.protobuf.ByteString.copyFrom(config.amfPublicKey))
            .setExpiration(com.google.protobuf.ByteString.copyFrom(config.enExpiration))
            .setProof(com.google.protobuf.ByteString.copyFrom(proof))
            .setPkePk(com.google.protobuf.ByteString.copyFrom(config.pkePublicKey))
            .setDrPk(com.google.protobuf.ByteString.copyFrom(config.drPublicKey))
            .build()
        
        android.util.Log.d(TAG, "Created AKE response for $callerPhoneNumber")
        return responseMessage
    }
    
    /**
     * Completes AKE on the caller side after receiving response.
     * Computes shared key and initializes Double Ratchet session.
     * 
     * @param callState The call state
     * @param responseMessage The AKE response from recipient
     * @param recipientPhoneNumber The recipient's phone number
     * @return true if successful, false if verification fails
     */
    fun akeComplete(
        callState: CallState,
        responseMessage: Protocol.AkeMessage,
        recipientPhoneNumber: String
    ): Boolean {
        val config = callState.config
        val nonce = callState.ake.topic
        
        // Verify the response proof
        if (!ZkProofs.verifyProofFromMessage(
            responseMessage,
            nonce,
            recipientPhoneNumber,
            config.raPublicKey
        )) {
            android.util.Log.e(TAG, "AKE response proof verification failed")
            return false
        }
        
        // Store peer's keys
        val peerDhPk = responseMessage.dhPk.toByteArray()
        val peerDrPk = responseMessage.drPk.toByteArray()
        
        callState.counterpartAmfPk = responseMessage.amfPk.toByteArray()
        callState.counterpartPkePk = responseMessage.pkePk.toByteArray()
        callState.counterpartDrPk = peerDrPk
        
        // Compute shared key from ephemeral DH
        val sharedKey = computeSharedKey(
            callState.ake.dhSk,
            peerDhPk,
            callState.ake.dhPk,
            peerDhPk
        )
        
        // Derive DR initialization key
        val drKey = deriveKey(sharedKey, AKE_DR_KEY_INFO.toByteArray())
        
        // Session ID from concatenated ephemeral public keys
        val sessionId = Utilities.hash(
            Utilities.concatBytes(callState.ake.dhPk, peerDhPk)
        )
        
        // Initialize Double Ratchet as caller (initiator)
        val drSession = DoubleRatchet.initAsCaller(
            sessionId = sessionId,
            sharedKey = drKey,
            remoteDrPk = peerDrPk
        )
        
        callState.drSession = drSession
        callState.setSharedKey(sharedKey)
        
        android.util.Log.d(TAG, "AKE completed as caller, DR session initialized")
        return true
    }
    
    /**
     * Finalizes AKE on the recipient side.
     * Computes shared key and initializes Double Ratchet session.
     * 
     * @param callState The call state with peer keys already stored from akeResponse
     * @param callerDhPk The caller's DH public key (from the original AKE request)
     * @return true if successful
     */
    fun akeFinalize(callState: CallState, callerDhPk: ByteArray): Boolean {
        val config = callState.config
        val peerDrPk = callState.counterpartDrPk
        
        // Compute shared key from ephemeral DH
        val sharedKey = computeSharedKey(
            callState.ake.dhSk,
            callerDhPk,
            callerDhPk,  // For recipient, caller's key comes first in ordering
            callState.ake.dhPk
        )
        
        // Derive DR initialization key  
        val drKey = deriveKey(sharedKey, AKE_DR_KEY_INFO.toByteArray())
        
        // Session ID from concatenated ephemeral public keys (same order as caller for consistency)
        val sessionId = Utilities.hash(
            Utilities.concatBytes(callerDhPk, callState.ake.dhPk)
        )
        
        // Initialize Double Ratchet as recipient
        val drSession = DoubleRatchet.initAsRecipient(
            sessionId = sessionId,
            sharedKey = drKey,
            drPrivateKey = config.drPrivateKey,
            drPublicKey = config.drPublicKey
        )
        
        callState.drSession = drSession
        callState.setSharedKey(sharedKey)
        
        android.util.Log.d(TAG, "AKE finalized as recipient, DR session initialized")
        return true
    }
    
    /**
     * Computes shared key using X25519 DH and HKDF.
     * 
     * @param localPrivateKey Our ephemeral private key
     * @param remotePublicKey Peer's ephemeral public key
     * @param initiatorPk Initiator's public key (for consistent key derivation)
     * @param responderPk Responder's public key (for consistent key derivation)
     * @return 32-byte shared key
     */
    private fun computeSharedKey(
        localPrivateKey: ByteArray,
        remotePublicKey: ByteArray,
        initiatorPk: ByteArray,
        responderPk: ByteArray
    ): ByteArray {
        // Perform X25519 DH
        val privateKeyParams = X25519PrivateKeyParameters(localPrivateKey, 0)
        val publicKeyParams = X25519PublicKeyParameters(remotePublicKey, 0)
        
        val agreement = X25519Agreement()
        agreement.init(privateKeyParams)
        
        val dhSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicKeyParams, dhSecret, 0)
        
        // Create salt from concatenated public keys (for consistent derivation)
        val salt = Utilities.concatBytes(initiatorPk, responderPk)
        
        // Derive final shared key using HKDF
        return deriveKey(dhSecret, AKE_SHARED_KEY_INFO.toByteArray(), salt)
    }
    
    /**
     * Derives a key using HKDF-SHA256.
     */
    private fun deriveKey(
        ikm: ByteArray,
        info: ByteArray,
        salt: ByteArray = ByteArray(32)
    ): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        
        val output = ByteArray(SHARED_KEY_SIZE)
        hkdf.generateBytes(output, 0, output.size)
        return output
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
