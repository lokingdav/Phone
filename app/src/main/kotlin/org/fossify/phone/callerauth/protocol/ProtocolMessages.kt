package org.fossify.phone.callerauth.protocol

import com.google.protobuf.ByteString
import denseid.protocol.v1.Protocol

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
     * Uses Double Ratchet session to decrypt if provided.
     */
    fun decodeRuaPayload(
        msg: Protocol.ProtocolMessage,
        drSession: DrSession? = null
    ): Protocol.RuaMessage {
        val payloadBytes = msg.payload.toByteArray()

        // If DR session is provided, decrypt the payload using Double Ratchet
        if (drSession != null) {
            val drMessage = Protocol.DrMessage.parseFrom(payloadBytes)
            val associatedData = msg.topic.toByteArray()
            val decrypted = DoubleRatchet.decrypt(drSession, drMessage, associatedData)
            return Protocol.RuaMessage.parseFrom(decrypted)
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
     * Uses Double Ratchet session to encrypt the payload.
     */
    fun createRuaMessage(
        senderId: String,
        topic: String,
        msgType: Protocol.MessageType,
        payload: Protocol.RuaMessage?,
        drSession: DrSession? = null
    ): ByteArray {
        var payloadBytes = ByteArray(0)

        if (payload != null) {
            payloadBytes = payload.toByteArray()

            // Encrypt payload using Double Ratchet if session is provided
            if (drSession != null) {
                val associatedData = topic.toByteArray()
                val drMessage = DoubleRatchet.encrypt(drSession, payloadBytes, associatedData)
                payloadBytes = drMessage.toByteArray()
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
