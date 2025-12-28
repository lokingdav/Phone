package org.fossify.phone.callerauth.protocol

import com.google.protobuf.ByteString
import denseid.protocol.v1.Protocol
import org.fossify.phone.callerauth.Pke

/**
 * Message type constants for convenience.
 */
object MessageType {
    val AKE_REQUEST = Protocol.MessageType.AKE_REQUEST
    val AKE_RESPONSE = Protocol.MessageType.AKE_RESPONSE
    val AKE_COMPLETE = Protocol.MessageType.AKE_COMPLETE
    val RUA_REQUEST = Protocol.MessageType.RUA_REQUEST
    val RUA_RESPONSE = Protocol.MessageType.RUA_RESPONSE
    val HEARTBEAT = Protocol.MessageType.HEARTBEAT
    val BYE = Protocol.MessageType.BYE
}

/**
 * Protocol message utilities for serialization/deserialization.
 */
object ProtocolMessages {

    /**
     * Serializes a ProtocolMessage to bytes.
     */
    fun marshalMessage(msg: Protocol.ProtocolMessage): ByteArray {
        require(msg.type != Protocol.MessageType.MESSAGE_TYPE_UNSPECIFIED) {
            "Missing message type"
        }
        return msg.toByteArray()
    }

    /**
     * Deserializes bytes into a ProtocolMessage.
     */
    fun unmarshalMessage(data: ByteArray): Protocol.ProtocolMessage {
        return Protocol.ProtocolMessage.parseFrom(data)
    }

    /**
     * Extracts AkeMessage from ProtocolMessage payload.
     * If pkePrivateKey is provided, the payload is decrypted first.
     */
    fun decodeAkePayload(msg: Protocol.ProtocolMessage, pkePrivateKey: ByteArray? = null): Protocol.AkeMessage {
        var payloadBytes = msg.payload.toByteArray()

        // If PKE key is provided, decrypt the payload first
        if (pkePrivateKey != null && pkePrivateKey.isNotEmpty()) {
            payloadBytes = Pke.decrypt(pkePrivateKey, payloadBytes)
        }

        return Protocol.AkeMessage.parseFrom(payloadBytes)
    }

    /**
     * Extracts RuaMessage from ProtocolMessage payload.
     * If sharedKey is provided, the payload is decrypted first using symmetric encryption.
     */
    fun decodeRuaPayload(msg: Protocol.ProtocolMessage, sharedKey: ByteArray? = null): Protocol.RuaMessage {
        var payloadBytes = msg.payload.toByteArray()

        // If shared key is provided, decrypt the payload first
        if (sharedKey != null && sharedKey.isNotEmpty()) {
            payloadBytes = SymmetricEncryption.decrypt(sharedKey, payloadBytes)
        }

        return Protocol.RuaMessage.parseFrom(payloadBytes)
    }

    // --- Message type checks ---

    fun isAkeRequest(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.AKE_REQUEST
    }

    fun isAkeResponse(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.AKE_RESPONSE
    }

    fun isAkeComplete(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.AKE_COMPLETE
    }

    fun isRuaRequest(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.RUA_REQUEST
    }

    fun isRuaResponse(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.RUA_RESPONSE
    }

    fun isHeartBeat(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.HEARTBEAT
    }

    fun isBye(msg: Protocol.ProtocolMessage): Boolean {
        return msg.type == Protocol.MessageType.BYE
    }

    // --- Message creation ---

    /**
     * Creates an AKE protocol message.
     * If recipientPkePk is provided, the payload is encrypted using PKE.
     */
    fun createAkeMessage(
        senderId: String,
        topic: String,
        msgType: Protocol.MessageType,
        payload: Protocol.AkeMessage?,
        recipientPkePk: ByteArray? = null
    ): ByteArray {
        var payloadBytes = ByteArray(0)

        if (payload != null) {
            payloadBytes = payload.toByteArray()

            // Encrypt payload if recipient's PKE public key is provided
            if (recipientPkePk != null && recipientPkePk.isNotEmpty()) {
                payloadBytes = Pke.encrypt(recipientPkePk, payloadBytes)
            }
        }

        val msg = Protocol.ProtocolMessage.newBuilder()
            .setType(msgType)
            .setSenderId(senderId)
            .setTopic(topic)
            .setPayload(ByteString.copyFrom(payloadBytes))
            .build()

        return marshalMessage(msg)
    }

    /**
     * Creates an RUA protocol message.
     * If sharedKey is provided, the payload is encrypted using symmetric encryption.
     */
    fun createRuaMessage(
        senderId: String,
        topic: String,
        msgType: Protocol.MessageType,
        payload: Protocol.RuaMessage?,
        sharedKey: ByteArray? = null
    ): ByteArray {
        var payloadBytes = ByteArray(0)

        if (payload != null) {
            payloadBytes = payload.toByteArray()

            // Encrypt payload if shared key is provided
            if (sharedKey != null && sharedKey.isNotEmpty()) {
                payloadBytes = SymmetricEncryption.encrypt(sharedKey, payloadBytes)
            }
        }

        val msg = Protocol.ProtocolMessage.newBuilder()
            .setType(msgType)
            .setSenderId(senderId)
            .setTopic(topic)
            .setPayload(ByteString.copyFrom(payloadBytes))
            .build()

        return marshalMessage(msg)
    }
}
