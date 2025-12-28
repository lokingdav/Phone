package org.fossify.phone.callerauth.protocol

import com.google.protobuf.ByteString
import denseid.protocol.v1.Protocol
import io.github.lokingdav.libdia.LibDia
import org.fossify.phone.callerauth.AMF
import org.fossify.phone.callerauth.Utilities

/**
 * Right-to-Use Authentication (RUA) protocol implementation.
 * 
 * RUA is the second phase after AKE, providing Right-to-Use (RTU) credential 
 * verification with call reason and display name.
 * 
 * Key difference from AKE: RUA uses AMF (Authenticated Message Franking) signatures
 * to enable moderation/reporting capabilities.
 * 
 * Protocol Flow:
 * 1. Caller: initRua() -> ruaRequest() -> sends RuaMessage to recipient
 * 2. Recipient: ruaResponse() -> verifies RTU and responds -> sends RuaMessage back
 * 3. Caller: ruaFinalize() -> verifies response, establishes final shared key
 * 
 * All messages are signed with AMF using:
 * - senderSk: sender's AMF private key
 * - receiverPk: receiver's AMF public key (from AKE exchange)
 * - judgePk: moderator public key (from enrollment)
 */
object Rua {
    private const val TAG = "Rua"
    
    /**
     * Creates an RTU (Right-to-Use) proto from the subscriber config.
     */
    private fun createRtuFromConfig(config: SubscriberConfig): Protocol.Rtu {
        return Protocol.Rtu.newBuilder()
            .setAmfPk(ByteString.copyFrom(config.amfPublicKey))
            .setPkePk(ByteString.copyFrom(config.pkePublicKey))
            .setDrPk(ByteString.copyFrom(config.drPublicKey))
            .setExpiration(ByteString.copyFrom(config.enExpiration))
            .setSignature(ByteString.copyFrom(config.raSignature))
            .setName(config.myName)
            .build()
    }
    
    /**
     * Derives the RUA topic from the shared key and call identifiers.
     */
    private fun deriveRuaTopic(callState: CallState): ByteArray {
        return Utilities.hashAll(
            callState.sharedKey,
            callState.src.toByteArray(Charsets.UTF_8),
            callState.dst.toByteArray(Charsets.UTF_8),
            callState.ts.toByteArray(Charsets.UTF_8)
        )
    }
    
    /**
     * Marshals RuaMessage deterministically for signing (DDA = Deterministic Data for Authentication).
     * This excludes the sigma field since it's what we're computing.
     * 
     * Matches Go's MarshalDDA function.
     */
    private fun marshalDDA(msg: Protocol.RuaMessage): ByteArray {
        val clone = msg.toBuilder().clearSigma().build()
        return clone.toByteArray()
    }
    
    /**
     * Initializes RUA state for the second protocol phase.
     * Generates new ephemeral DH keypair for RUA and creates RTU.
     */
    fun initRua(callState: CallState): Boolean {
        val config = callState.config ?: return false
        
        // Generate ephemeral DH keypair
        val (dhSk, dhPk) = try {
            LibDia.dhKeygen()
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to generate DH keypair: ${e.message}")
            return false
        }
        
        // Derive RUA topic from shared key
        val ruaTopic = deriveRuaTopic(callState)
        
        // Create RTU from config
        val rtu = createRtuFromConfig(config)
        
        // Update call state
        callState.rua.dhSk = dhSk
        callState.rua.dhPk = dhPk
        callState.rua.topic = ruaTopic
        callState.rua.rtu = rtu
        
        android.util.Log.d(TAG, "Initialized RUA with topic: ${Utilities.encodeToHex(ruaTopic).take(16)}...")
        return true
    }
    
    /**
     * Creates an RUA request message (caller side).
     * 
     * Per Go implementation: Sign MarshalDDA(ruaMsg) with AMF.
     * 
     * @param callState The call state
     * @param reason The call reason to include
     * @return RuaMessage protobuf to send to recipient
     */
    fun ruaRequest(callState: CallState, reason: String): Protocol.RuaMessage? {
        val config = callState.config ?: return null
        val counterpartAmfPk = callState.counterpartAmfPk ?: return null
        
        // Ensure RUA is initialized
        if (callState.rua.topic.isEmpty()) {
            if (!initRua(callState)) {
                return null
            }
        }
        
        val topic = Utilities.encodeToHex(callState.rua.topic)
        
        // Build RuaMessage without sigma first
        val ruaMsg = Protocol.RuaMessage.newBuilder()
            .setDhPk(ByteString.copyFrom(callState.rua.dhPk))
            .setTpc(topic)
            .setReason(reason)
            .setRtu(callState.rua.rtu)
            .build()
        
        // Get deterministic bytes for signing (excludes sigma)
        val data = marshalDDA(ruaMsg)
        
        // Sign with AMF: sign(senderSk, receiverPk, judgePk, message)
        val sigma = try {
            AMF.sign(
                config.amfPrivateKey,
                counterpartAmfPk,
                config.moderatorPublicKey,
                data
            )
        } catch (e: Exception) {
            android.util.Log.e(TAG, "AMF sign failed: ${e.message}")
            return null
        }
        
        // Build final message with sigma
        val signedRuaMsg = ruaMsg.toBuilder()
            .setSigma(ByteString.copyFrom(sigma))
            .build()
        
        // Store request for later verification
        callState.rua.req = signedRuaMsg
        callState.callReason = reason
        
        // Transition to RUA topic
        callState.transitionToRua(callState.rua.topic)
        
        android.util.Log.d(TAG, "Created RUA request with reason: $reason")
        return signedRuaMsg
    }
    
    /**
     * Verifies the RTU (Right-to-Use credential) from the caller.
     * This verifies the BBS signature from the Registration Authority.
     * 
     * @param party The verifier's call state
     * @param tn The telephone number claimed by the sender
     * @param msg The RuaMessage containing RTU
     * @return true if RTU is valid
     */
    fun verifyRTU(party: CallState, tn: String, msg: Protocol.RuaMessage): Boolean {
        val config = party.config ?: return false
        val rtu = msg.rtu
        
        // Verify BBS signature on RTU contents
        // message1 = hash(amf_pk || pke_pk || dr_pk || expiration || telephone_number)
        // message2 = name
        val message1 = Utilities.hashAll(
            rtu.amfPk.toByteArray(),
            rtu.pkePk.toByteArray(),
            rtu.drPk.toByteArray(),
            rtu.expiration.toByteArray(),
            tn.toByteArray(Charsets.UTF_8)
        )
        val message2 = rtu.name.toByteArray(Charsets.UTF_8)
        
        val rtuValid = try {
            ZkProofs.verifyRtuSignature(
                config.raPublicKey,
                rtu.signature.toByteArray(),
                message1,
                message2
            )
        } catch (e: Exception) {
            android.util.Log.e(TAG, "BBS verification failed: ${e.message}")
            false
        }
        
        if (!rtuValid) {
            android.util.Log.e(TAG, "RTU signature verification failed for $tn")
            return false
        }
        
        // Verify AMF sigma signature
        // verify(senderPk, receiverSk, judgePk, message, signature)
        val data = marshalDDA(msg)
        val sigmaValid = try {
            AMF.verify(
                rtu.amfPk.toByteArray(),     // sender's AMF public key
                config.amfPrivateKey,         // receiver's AMF private key
                config.moderatorPublicKey,    // moderator public key
                data,
                msg.sigma.toByteArray()
            )
        } catch (e: Exception) {
            android.util.Log.e(TAG, "AMF verification failed: ${e.message}")
            false
        }
        
        if (!sigmaValid) {
            android.util.Log.e(TAG, "AMF signature verification failed")
            return false
        }
        
        android.util.Log.d(TAG, "RTU verified for $tn (${rtu.name})")
        return true
    }
    
    /**
     * Processes an incoming RUA request and creates a response (recipient side).
     * 
     * Per Go implementation: 
     * - Verify caller's RTU and AMF signature
     * - Create response with own RTU
     * - Sign response with AMF over {DhPk, Rtu, Misc=ddA}
     * 
     * @param callState The call state
     * @param incomingMessage The received RUA request from caller
     * @return RuaMessage protobuf to send back, or null if verification fails
     */
    fun ruaResponse(callState: CallState, incomingMessage: Protocol.RuaMessage): Protocol.RuaMessage? {
        val config = callState.config ?: return null
        
        // Get caller's telephone number (source of the call)
        val callerTn = callState.src
        
        // Verify the caller's RTU and AMF signature
        if (!verifyRTU(callState, callerTn, incomingMessage)) {
            android.util.Log.e(TAG, "RUA request RTU verification failed")
            return null
        }
        
        // Ensure RUA is initialized
        if (callState.rua.topic.isEmpty()) {
            if (!initRua(callState)) {
                return null
            }
        }
        
        // Store caller's RTU info
        callState.counterpartAmfPk = incomingMessage.rtu.amfPk.toByteArray()
        callState.counterpartPkePk = incomingMessage.rtu.pkePk.toByteArray()
        callState.counterpartDrPk = incomingMessage.rtu.drPk.toByteArray()
        
        // Get deterministic bytes of caller's request (ddA)
        val ddA = marshalDDA(incomingMessage)
        
        // Build response message: {DhPk, Rtu, Misc=ddA}
        // Per Go: reply := &RuaMessage{DhPk, Rtu, Misc: ddA}
        val reply = Protocol.RuaMessage.newBuilder()
            .setDhPk(ByteString.copyFrom(callState.rua.dhPk))
            .setRtu(callState.rua.rtu)
            .setMisc(ByteString.copyFrom(ddA))
            .build()
        
        // Get deterministic bytes for signing
        val ddB = marshalDDA(reply)
        
        // Sign with AMF
        val sigma = try {
            AMF.sign(
                config.amfPrivateKey,
                callState.counterpartAmfPk!!,
                config.moderatorPublicKey,
                ddB
            )
        } catch (e: Exception) {
            android.util.Log.e(TAG, "AMF sign failed: ${e.message}")
            return null
        }
        
        // Compute new shared key
        val secret = try {
            LibDia.dhComputeSecret(callState.rua.dhSk, incomingMessage.dhPk.toByteArray())
        } catch (e: Exception) {
            android.util.Log.e(TAG, "DH compute secret failed: ${e.message}")
            return null
        }
        
        // Per Go: sharedKey = HashAll(ddA, rtuB, secret, caller.DhPk, recipient.DhPk)
        val rtuB = incomingMessage.rtu.toByteArray()
        val newSharedKey = Utilities.hashAll(
            ddA,
            rtuB,
            secret,
            incomingMessage.dhPk.toByteArray(),
            callState.rua.dhPk
        )
        callState.setSharedKey(newSharedKey)
        
        // Build final message with sigma
        val signedReply = reply.toBuilder()
            .setSigma(ByteString.copyFrom(sigma))
            .build()
        
        android.util.Log.d(TAG, "Created RUA response, shared key established")
        return signedReply
    }
    
    /**
     * Completes RUA on the caller side after receiving response.
     * 
     * Per Go implementation:
     * - Verify recipient's RTU and AMF signature
     * - Verify that Misc matches our original request's DDA
     * - Compute shared key
     * 
     * @param callState The call state
     * @param responseMessage The RUA response from recipient
     * @return true if successful, false if verification fails
     */
    fun ruaFinalize(callState: CallState, responseMessage: Protocol.RuaMessage): Boolean {
        val config = callState.config ?: return false
        
        // Get recipient's telephone number (destination of the call)
        val recipientTn = callState.dst
        
        // Get deterministic bytes of our original request (ddA)
        val originalReq = callState.rua.req ?: return false
        val ddA = marshalDDA(originalReq)
        
        // Verify that Misc field matches our original request's DDA
        if (!ddA.contentEquals(responseMessage.misc.toByteArray())) {
            android.util.Log.e(TAG, "RUA response Misc field mismatch - possible replay attack")
            return false
        }
        
        // Build the message that was signed: {DhPk, Rtu, Misc=ddA}
        val signedMsg = Protocol.RuaMessage.newBuilder()
            .setDhPk(responseMessage.dhPk)
            .setRtu(responseMessage.rtu)
            .setMisc(responseMessage.misc)
            .build()
        
        val signedData = marshalDDA(signedMsg)
        
        // Verify AMF signature
        val sigmaValid = try {
            AMF.verify(
                responseMessage.rtu.amfPk.toByteArray(),  // sender's AMF public key
                config.amfPrivateKey,                      // receiver's AMF private key
                config.moderatorPublicKey,                 // moderator public key
                signedData,
                responseMessage.sigma.toByteArray()
            )
        } catch (e: Exception) {
            android.util.Log.e(TAG, "AMF verification failed: ${e.message}")
            false
        }
        
        if (!sigmaValid) {
            android.util.Log.e(TAG, "RUA response AMF signature verification failed")
            return false
        }
        
        // Store recipient's info
        callState.counterpartAmfPk = responseMessage.rtu.amfPk.toByteArray()
        callState.counterpartPkePk = responseMessage.rtu.pkePk.toByteArray()
        callState.counterpartDrPk = responseMessage.rtu.drPk.toByteArray()
        
        // Compute shared key
        val secret = try {
            LibDia.dhComputeSecret(callState.rua.dhSk, responseMessage.dhPk.toByteArray())
        } catch (e: Exception) {
            android.util.Log.e(TAG, "DH compute secret failed: ${e.message}")
            return false
        }
        
        // Per Go: Use caller's RTU (from original request) for shared key
        val rtuA = originalReq.rtu.toByteArray()
        val newSharedKey = Utilities.hashAll(
            ddA,
            rtuA,
            secret,
            callState.rua.dhPk,
            responseMessage.dhPk.toByteArray()
        )
        callState.setSharedKey(newSharedKey)
        
        android.util.Log.d(TAG, "RUA completed, shared key established")
        return true
    }
    
    /**
     * Gets the RTU (Right-to-Use) info for the counterpart after RUA completion.
     */
    fun getCounterpartRtu(callState: CallState): RtuInfo? {
        val rtu = callState.rua.rtu ?: return null
        
        return RtuInfo(
            displayName = rtu.name,
            amfPublicKey = rtu.amfPk.toByteArray(),
            pkePublicKey = rtu.pkePk.toByteArray(),
            drPublicKey = rtu.drPk.toByteArray()
        )
    }
    
    /**
     * Rich Telephone User information.
     */
    data class RtuInfo(
        val displayName: String,
        val amfPublicKey: ByteArray,
        val pkePublicKey: ByteArray,
        val drPublicKey: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RtuInfo) return false
            return displayName == other.displayName &&
                amfPublicKey.contentEquals(other.amfPublicKey)
        }

        override fun hashCode(): Int = displayName.hashCode()
    }
}
