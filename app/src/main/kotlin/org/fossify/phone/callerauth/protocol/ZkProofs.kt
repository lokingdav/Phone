package org.fossify.phone.callerauth.protocol

import denseid.protocol.v1.Protocol
import io.github.lokingdav.libdia.LibDia
import org.fossify.phone.callerauth.Utilities

/**
 * BBS+ Zero-Knowledge Proof parameters for AKE.
 */
data class AkeZkProofParams(
    val tn: String,
    val name: String,
    val amfPublicKey: ByteArray,
    val pkePublicKey: ByteArray,
    val drPublicKey: ByteArray,
    val expiration: ByteArray,
    val nonce: ByteArray,
    val raPublicKey: ByteArray,
    val signature: ByteArray = ByteArray(0),
    val proof: ByteArray = ByteArray(0)
)

/**
 * BBS+ Zero-Knowledge Proof utilities for AKE protocol.
 */
object ZkProofs {

    /**
     * Creates a ZK proof for AKE authentication.
     * 
     * The BBS signature is over 2 messages:
     * - message1 = hash(amf_pk || pke_pk || dr_pk || expiration || telephone_number)
     * - message2 = name (display name)
     * 
     * The proof reveals message1 (index 1) but hides message2 (name).
     */
    fun createProof(params: AkeZkProofParams): ByteArray {
        // message1: hash of public attributes
        val message1 = Utilities.hashAll(
            params.amfPublicKey,
            params.pkePublicKey,
            params.drPublicKey,
            params.expiration,
            params.tn.toByteArray(Charsets.UTF_8)
        )
        // message2: name (will be hidden in the proof)
        val message2 = params.name.toByteArray(Charsets.UTF_8)

        val messages = arrayOf(message1, message2)

        // Disclose index 1 (message1) - using 1-based indexing as per LibDia API
        val disclosedIndices = intArrayOf(1)

        return LibDia.bbsCreateProof(
            messages,
            disclosedIndices,
            params.raPublicKey,
            params.signature,
            params.nonce
        )
    }

    /**
     * Creates a ZK proof from SubscriberConfig for AKE authentication.
     */
    fun createProofFromConfig(config: SubscriberConfig, nonce: ByteArray): ByteArray {
        val params = AkeZkProofParams(
            tn = config.myPhone,
            name = config.myName,
            amfPublicKey = config.amfPublicKey,
            pkePublicKey = config.pkePublicKey,
            drPublicKey = config.drPublicKey,
            expiration = config.enExpiration,
            nonce = nonce,
            raPublicKey = config.raPublicKey,
            signature = config.raSignature
        )
        return createProof(params)
    }

    /**
     * Verifies a ZK proof for AKE authentication.
     * 
     * Reconstructs message1 from the provided public attributes and verifies
     * that the proof is valid under the RA's public key.
     */
    fun verifyProof(params: AkeZkProofParams): Boolean {
        // Reconstruct message1 from public attributes
        val message1 = Utilities.hashAll(
            params.amfPublicKey,
            params.pkePublicKey,
            params.drPublicKey,
            params.expiration,
            params.tn.toByteArray(Charsets.UTF_8)
        )

        // Disclosed messages (only message1)
        val disclosedMessages = arrayOf(message1)

        // Disclosed indices (1-based)
        val disclosedIndices = intArrayOf(1)

        return LibDia.bbsVerifyProof(
            disclosedIndices,
            disclosedMessages,
            params.raPublicKey,
            params.nonce,
            params.proof
        )
    }

    /**
     * Verifies a ZK proof from an incoming AkeMessage.
     * 
     * @param message The incoming AkeMessage
     * @param nonce The nonce used for the proof (typically the AKE topic)
     * @param phoneNumber The expected phone number (from caller ID or context)
     * @param raPublicKey The RA's public key for verification
     * @return true if the proof is valid
     */
    fun verifyProofFromMessage(
        message: Protocol.AkeMessage,
        nonce: ByteArray,
        phoneNumber: String,
        raPublicKey: ByteArray
    ): Boolean {
        val params = AkeZkProofParams(
            tn = phoneNumber,
            name = "",  // Hidden in the proof
            amfPublicKey = message.amfPk.toByteArray(),
            pkePublicKey = message.pkePk.toByteArray(),
            drPublicKey = message.drPk.toByteArray(),
            expiration = message.expiration.toByteArray(),
            nonce = nonce,
            raPublicKey = raPublicKey,
            proof = message.proof.toByteArray()
        )
        return verifyProof(params)
    }

    /**
     * Verifies the RTU (Right-to-Use) BBS signature from the Registration Authority.
     * 
     * The BBS signature covers 2 messages:
     * - message1: hash(amf_pk || pke_pk || dr_pk || expiration || telephone_number)
     * - message2: display name
     * 
     * @param raPublicKey The RA's BBS public key
     * @param signature The BBS signature from the RA
     * @param message1 The hashed public attributes
     * @param message2 The display name bytes
     * @return true if signature is valid
     */
    fun verifyRtuSignature(
        raPublicKey: ByteArray,
        signature: ByteArray,
        message1: ByteArray,
        message2: ByteArray
    ): Boolean {
        return LibDia.bbsVerify(
            arrayOf(message1, message2),
            raPublicKey,
            signature
        )
    }
}
