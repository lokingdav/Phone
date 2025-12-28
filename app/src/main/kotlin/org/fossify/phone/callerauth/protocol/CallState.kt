package org.fossify.phone.callerauth.protocol

import denseid.protocol.v1.Protocol
import org.fossify.phone.callerauth.Utilities
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * AKE (Authenticated Key Exchange) state.
 */
data class AkeState(
    var topic: ByteArray = ByteArray(0),
    var dhSk: ByteArray = ByteArray(0),
    var dhPk: ByteArray = ByteArray(0),
    var chal0: ByteArray = ByteArray(0),
    var callerProof: ByteArray = ByteArray(0),
    var recipientProof: ByteArray = ByteArray(0)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AkeState) return false
        return topic.contentEquals(other.topic)
    }

    override fun hashCode(): Int = topic.contentHashCode()
}

/**
 * RUA (Right-to-Use Authentication) state.
 */
data class RuaState(
    var topic: ByteArray = ByteArray(0),
    var dhSk: ByteArray = ByteArray(0),
    var dhPk: ByteArray = ByteArray(0),
    var rtu: Protocol.Rtu? = null,
    var req: Protocol.RuaMessage? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RuaState) return false
        return topic.contentEquals(other.topic)
    }

    override fun hashCode(): Int = topic.contentHashCode()
}

/**
 * Call state management for protocol operations.
 * Thread-safe wrapper for all call-related state.
 */
class CallState(
    val config: SubscriberConfig,
    phoneNumber: String,
    val isOutgoing: Boolean
) {
    private val lock = ReentrantLock()

    // Parties
    val src: String
    val dst: String
    val ts: String = getNormalizedTs()
    val senderId: String = UUID.randomUUID().toString()

    // State
    var currentTopic: ByteArray = ByteArray(0)
        private set
    var ruaActive: Boolean = false
        private set
    var ticket: ByteArray = config.sampleTicket
        private set
    var sharedKey: ByteArray = ByteArray(0)
        private set
    var callReason: String = ""

    // Counterpart info (populated during AKE)
    var counterpartAmfPk: ByteArray = ByteArray(0)
    var counterpartPkePk: ByteArray = ByteArray(0)
    var counterpartDrPk: ByteArray = ByteArray(0)

    // Protocol states
    val ake = AkeState()
    val rua = RuaState()

    // Double Ratchet session
    var drSession: DrSession? = null

    init {
        if (isOutgoing) {
            src = config.myPhone
            dst = phoneNumber
        } else {
            src = phoneNumber
            dst = config.myPhone
        }
    }

    fun getAkeLabel(): ByteArray = (src + ts).toByteArray(Charsets.UTF_8)

    fun getAkeTopic(): String = lock.withLock {
        Utilities.encodeToHex(ake.topic)
    }

    fun iamCaller(): Boolean = isOutgoing

    fun iamRecipient(): Boolean = !isOutgoing

    fun initAke(dhSk: ByteArray, dhPk: ByteArray, akeTopic: ByteArray) = lock.withLock {
        ake.dhSk = dhSk
        ake.dhPk = dhPk
        ake.topic = akeTopic
        currentTopic = akeTopic
        ruaActive = false
    }

    /**
     * Transitions to RUA phase. AKE topic is preserved for AkeComplete.
     */
    fun transitionToRua(ruaTopic: ByteArray) = lock.withLock {
        rua.topic = ruaTopic
        currentTopic = ruaTopic
        ruaActive = true
    }

    fun getCurrentTopic(): String = lock.withLock {
        Utilities.encodeToHex(currentTopic)
    }

    fun isRuaActive(): Boolean = lock.withLock { ruaActive }

    fun setSharedKey(key: ByteArray) = lock.withLock {
        sharedKey = key
    }

    fun updateCaller(chal: ByteArray, proof: ByteArray) = lock.withLock {
        ake.chal0 = chal
        ake.callerProof = proof
    }

    companion object {
        private val formatter = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH")
            .withZone(ZoneOffset.UTC)

        /**
         * Returns a normalized timestamp (hourly granularity for topic derivation).
         */
        fun getNormalizedTs(): String {
            return formatter.format(Instant.now())
        }
    }
}
