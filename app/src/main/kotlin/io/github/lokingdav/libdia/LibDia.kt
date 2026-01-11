package io.github.lokingdav.libdia

/**
 * LibDia - Dynamic Identity Authentication library for Android
 *
 * This library provides the DIA Protocol implementation for:
 * - Authenticated Key Exchange (AKE)
 * - Right-To-Use Authentication (RUA)
 * - Double Ratchet secure messaging (DR)
 * - Enrollment and credential management
 */
object LibDia {
    init { System.loadLibrary("dia_jni") }

    // ===================== Message Type Constants =====================
    const val MSG_UNSPECIFIED = 0
    const val MSG_AKE_REQUEST = 1
    const val MSG_AKE_RESPONSE = 2
    const val MSG_AKE_COMPLETE = 3
    const val MSG_RUA_REQUEST = 4
    const val MSG_RUA_RESPONSE = 5
    const val MSG_HEARTBEAT = 6
    const val MSG_BYE = 7
    const val MSG_ODA_REQUEST = 8
    const val MSG_ODA_RESPONSE = 9

    // ===================== Config =====================
    /** Parse a Config from environment variable format string. Returns native handle. */
    external fun configFromEnv(envContent: String): Long

    /** Serialize a Config to environment variable format string. */
    external fun configToEnv(handle: Long): String

    /** Free a Config handle. */
    external fun configDestroy(handle: Long)

    // ===================== CallState =====================
    /** Create a new CallState for a call. Returns native handle. */
    external fun callStateCreate(configHandle: Long, phone: String, outgoing: Boolean): Long

    /** Free a CallState handle. */
    external fun callStateDestroy(handle: Long)

    /** Get the AKE topic (hex string). */
    external fun callStateGetAkeTopic(handle: Long): String

    /** Get the current active topic (hex string). */
    external fun callStateGetCurrentTopic(handle: Long): String

    /** Get the shared key (available after AKE completes). */
    external fun callStateGetSharedKey(handle: Long): ByteArray

    /** Get the access ticket. */
    external fun callStateGetTicket(handle: Long): ByteArray

    /** Get the sender ID. */
    external fun callStateGetSenderId(handle: Long): String

    /** Returns true if this is an outgoing call (we are the caller). */
    external fun callStateIsCaller(handle: Long): Boolean

    /** Returns true if this is an incoming call (we are the recipient). */
    external fun callStateIsRecipient(handle: Long): Boolean

    /** Returns true if the RUA phase is active. */
    external fun callStateIsRuaActive(handle: Long): Boolean

    /** Get remote party info as [phone, name, logo, verified]. Populated after RUA. */
    external fun callStateGetRemoteParty(handle: Long): Array<String>

    /** Transition to RUA topic (updates current topic). */
    external fun callStateTransitionToRua(handle: Long)

    // ===================== AKE Protocol =====================
    /** Initialize AKE state (generates DH keys, computes topic). */
    external fun akeInit(callStateHandle: Long)

    /** Caller: Create AKE request message. */
    external fun akeRequest(callStateHandle: Long): ByteArray

    /** Recipient: Process AKE request, create AKE response. */
    external fun akeResponse(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Caller: Process AKE response, create AKE complete message. */
    external fun akeComplete(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Recipient: Process AKE complete, finalize AKE. */
    external fun akeFinalize(callStateHandle: Long, msgData: ByteArray)

    // ===================== RUA Protocol =====================
    /** Derive RUA topic from shared key. */
    external fun ruaDeriveTopic(callStateHandle: Long): String

    /** Initialize RTU for RUA phase. */
    external fun ruaInit(callStateHandle: Long)

    /** Caller: Create RUA request message. */
    external fun ruaRequest(callStateHandle: Long): ByteArray

    /** Recipient: Process RUA request, create RUA response. */
    external fun ruaResponse(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Caller: Process RUA response, finalize RUA. */
    external fun ruaFinalize(callStateHandle: Long, msgData: ByteArray)

    // ===================== ODA Protocol =====================
    /** Verifier: Create an ODA request for the specified attributes. */
    external fun odaRequest(callStateHandle: Long, attributes: Array<String>): ByteArray

    /** Prover: Process an ODA request and create an ODA response. */
    external fun odaResponse(callStateHandle: Long, msgData: ByteArray): ByteArray

    /** Verifier: Verify an ODA response and return flattened verification info. */
    external fun odaVerify(callStateHandle: Long, msgData: ByteArray): Array<String>

    /** Returns the number of ODA verifications performed. */
    external fun odaGetVerificationCount(callStateHandle: Long): Int

    /** Retrieves a specific ODA verification (flattened) by index. */
    external fun odaGetVerification(callStateHandle: Long, index: Int): Array<String>

    // ===================== Messages =====================
    /** Deserialize a protocol message. Returns native handle. */
    external fun messageDeserialize(data: ByteArray): Long

    /** Free a message handle. */
    external fun messageDestroy(handle: Long)

    /** Get message type (MSG_* constant). */
    external fun messageGetType(handle: Long): Int

    /** Get sender ID from message. */
    external fun messageGetSenderId(handle: Long): String

    /** Get topic from message. */
    external fun messageGetTopic(handle: Long): String

    /** Create a Bye message. */
    external fun messageCreateBye(callStateHandle: Long): ByteArray

    /** Create a Heartbeat message. */
    external fun messageCreateHeartbeat(callStateHandle: Long): ByteArray

    // ===================== DR Messaging =====================
    /** Encrypt a message using Double Ratchet. */
    external fun drEncrypt(callStateHandle: Long, plaintext: ByteArray): ByteArray

    /** Decrypt a message using Double Ratchet. */
    external fun drDecrypt(callStateHandle: Long, ciphertext: ByteArray): ByteArray

    // ===================== Enrollment =====================
    /**
     * Create an enrollment request.
     * Returns [[keysHandle (8 bytes)], [request bytes]]
     */
    external fun enrollmentCreateRequest(
        phone: String,
        name: String,
        logoUrl: String?,
        numTickets: Int
    ): Array<ByteArray>

    /**
     * Finalize enrollment after receiving server response.
     * Returns config handle.
     */
    external fun enrollmentFinalize(
        keysHandle: ByteArray,
        response: ByteArray,
        phone: String,
        name: String,
        logoUrl: String?
    ): Long

    /** Free enrollment keys handle. */
    external fun enrollmentKeysDestroy(keysHandle: ByteArray)

    // ===================== Ticket Verification =====================
    /** Verify a ticket using the VOPRF verification key. */
    external fun verifyTicket(ticket: ByteArray, verifyKey: ByteArray): Boolean
}

// ===================== High-Level Kotlin API =====================

/**
 * Represents remote party information after successful RUA.
 */
data class RemoteParty(
    val phone: String,
    val name: String,
    val logo: String,
    val verified: Boolean
)

/**
 * Result of an On-Demand Authentication (ODA) verification.
 */
data class OdaVerification(
    val timestamp: String,
    val verified: Boolean,
    val issuer: String,
    val credentialType: String,
    val issuanceDate: String,
    val expirationDate: String,
    val disclosedAttributes: Map<String, String>
)

/**
 * DIA client configuration with automatic resource management.
 *
 * Example usage:
 * ```kotlin
 * DiaConfig.fromEnv(envString).use { config ->
 *     val envStr = config.toEnv()
 *     // config automatically cleaned up
 * }
 * ```
 */
class DiaConfig private constructor(internal val handle: Long) : AutoCloseable {
    companion object {
        /**
         * Parse a ClientConfig from environment variable format string.
         * Format: KEY=value lines (byte values are hex-encoded).
         *
         * @param envContent Environment variable format string
         * @return DiaConfig instance
         * @throws IllegalStateException if parsing fails
         */
        fun fromEnv(envContent: String): DiaConfig {
            val handle = LibDia.configFromEnv(envContent)
            if (handle == 0L) throw IllegalStateException("Failed to parse config")
            return DiaConfig(handle)
        }
    }

    /**
     * Serialize this config to environment variable format string.
     *
     * @return Environment variable format string
     */
    fun toEnv(): String = LibDia.configToEnv(handle)

    override fun close() {
        if (handle != 0L) {
            LibDia.configDestroy(handle)
        }
    }
}

/**
 * Manages the state for a DIA call session with automatic resource management.
 *
 * Example usage:
 * ```kotlin
 * config.use { cfg ->
 *     CallState.create(cfg, "+1234567890", outgoing = true).use { call ->
 *         // Perform AKE and RUA
 *         call.akeInit()
 *         val request = call.akeRequest()
 *         // ... protocol flow
 *     }
 * }
 * ```
 */
class CallState private constructor(internal val handle: Long) : AutoCloseable {
    companion object {
        /**
         * Create a new call state for a call session.
         *
         * @param config Client configuration
         * @param phone Other party's phone number
         * @param outgoing true for outgoing calls (caller), false for incoming (recipient)
         * @return CallState instance
         * @throws IllegalStateException if creation fails
         */
        fun create(config: DiaConfig, phone: String, outgoing: Boolean): CallState {
            val handle = LibDia.callStateCreate(config.handle, phone, outgoing)
            if (handle == 0L) throw IllegalStateException("Failed to create CallState")
            return CallState(handle)
        }
    }

    /** Get the AKE topic as a hex string. */
    val akeTopic: String get() = LibDia.callStateGetAkeTopic(handle)

    /** Get the current active topic as a hex string. */
    val currentTopic: String get() = LibDia.callStateGetCurrentTopic(handle)

    /** Get the shared key (available after AKE completes). */
    val sharedKey: ByteArray get() = LibDia.callStateGetSharedKey(handle)

    /** Get the access ticket. */
    val ticket: ByteArray get() = LibDia.callStateGetTicket(handle)

    /** Get the sender ID for this party. */
    val senderId: String get() = LibDia.callStateGetSenderId(handle)

    /** Returns true if this is an outgoing call (we are the caller). */
    val isCaller: Boolean get() = LibDia.callStateIsCaller(handle)

    /** Returns true if this is an incoming call (we are the recipient). */
    val isRecipient: Boolean get() = LibDia.callStateIsRecipient(handle)

    /** Returns true if the RUA phase is active. */
    val isRuaActive: Boolean get() = LibDia.callStateIsRuaActive(handle)

    /**
     * Get remote party information (populated after RUA completes).
     *
     * @return RemoteParty with verified identity information
     */
    val remoteParty: RemoteParty
        get() {
            val arr = LibDia.callStateGetRemoteParty(handle)
            return RemoteParty(
                phone = arr[0],
                name = arr[1],
                logo = arr[2],
                verified = arr[3] == "true"
            )
        }

    /** Transition to RUA topic (updates current topic). */
    fun transitionToRua() = LibDia.callStateTransitionToRua(handle)

    // ===================== AKE Protocol =====================

    /** Initialize AKE state (generates DH keys, computes topic). */
    fun akeInit() = LibDia.akeInit(handle)

    /** Caller: Create AKE request message. */
    fun akeRequest(): ByteArray = LibDia.akeRequest(handle)

    /** Recipient: Process AKE request, create AKE response. */
    fun akeResponse(msgData: ByteArray): ByteArray = LibDia.akeResponse(handle, msgData)

    /** Caller: Process AKE response, create AKE complete message. */
    fun akeComplete(msgData: ByteArray): ByteArray = LibDia.akeComplete(handle, msgData)

    /** Recipient: Process AKE complete, finalize AKE. */
    fun akeFinalize(msgData: ByteArray) = LibDia.akeFinalize(handle, msgData)

    // ===================== RUA Protocol =====================

    /** Derive RUA topic from shared key. */
    fun ruaDeriveTopic(): String = LibDia.ruaDeriveTopic(handle)

    /** Initialize RTU for RUA phase. */
    fun ruaInit() = LibDia.ruaInit(handle)

    /** Caller: Create RUA request message. */
    fun ruaRequest(): ByteArray = LibDia.ruaRequest(handle)

    /** Recipient: Process RUA request, create RUA response. */
    fun ruaResponse(msgData: ByteArray): ByteArray = LibDia.ruaResponse(handle, msgData)

    /** Caller: Process RUA response, finalize RUA. */
    fun ruaFinalize(msgData: ByteArray) = LibDia.ruaFinalize(handle, msgData)

    // ===================== ODA Protocol =====================

    /**
     * Verifier: Create an ODA request for the specified attributes.
     * Returns encrypted ODA request bytes.
     */
    fun odaRequest(attributes: List<String>): ByteArray =
        LibDia.odaRequest(handle, attributes.toTypedArray())

    /**
     * Prover: Process an encrypted ODA request and create an encrypted ODA response.
     */
    fun odaResponse(msgData: ByteArray): ByteArray = LibDia.odaResponse(handle, msgData)

    /**
     * Verifier: Verify an encrypted ODA response and return structured verification info.
     */
    fun odaVerify(msgData: ByteArray): OdaVerification = parseOdaVerification(LibDia.odaVerify(handle, msgData))

    /** Number of ODA verifications performed in this CallState. */
    val odaVerificationCount: Int get() = LibDia.odaGetVerificationCount(handle)

    /** Get ODA verification info by index (0..count-1). */
    fun odaGetVerification(index: Int): OdaVerification =
        parseOdaVerification(LibDia.odaGetVerification(handle, index))

    // ===================== Messages =====================

    /** Create a Bye message for ending the call. */
    fun createByeMessage(): ByteArray = LibDia.messageCreateBye(handle)

    /** Create a Heartbeat message for keep-alive. */
    fun createHeartbeatMessage(): ByteArray = LibDia.messageCreateHeartbeat(handle)

    // ===================== DR Messaging =====================

    /**
     * Encrypt a message using Double Ratchet (available after RUA).
     *
     * @param plaintext Message to encrypt
     * @return Encrypted ciphertext
     */
    fun encrypt(plaintext: ByteArray): ByteArray = LibDia.drEncrypt(handle, plaintext)

    /**
     * Decrypt a message using Double Ratchet (available after RUA).
     *
     * @param ciphertext Encrypted message
     * @return Decrypted plaintext
     */
    fun decrypt(ciphertext: ByteArray): ByteArray = LibDia.drDecrypt(handle, ciphertext)

    override fun close() {
        if (handle != 0L) {
            LibDia.callStateDestroy(handle)
        }
    }
}

private fun parseOdaVerification(flat: Array<String>): OdaVerification {
    // Flattened format from JNI:
    // [timestamp, verified("true"/"false"), issuer, credentialType, issuanceDate, expirationDate, name0, value0, ...]
    if (flat.size < 6) throw IllegalStateException("Invalid ODA verification data")
    val attrs = LinkedHashMap<String, String>()
    var i = 6
    while (i + 1 < flat.size) {
        attrs[flat[i]] = flat[i + 1]
        i += 2
    }
    return OdaVerification(
        timestamp = flat[0],
        verified = flat[1] == "true",
        issuer = flat[2],
        credentialType = flat[3],
        issuanceDate = flat[4],
        expirationDate = flat[5],
        disclosedAttributes = attrs
    )
}

/**
 * Protocol message wrapper with automatic resource management.
 *
 * Example usage:
 * ```kotlin
 * DiaMessage.parse(messageBytes).use { msg ->
 *     when {
 *         msg.isAkeRequest -> handleAkeRequest(msg)
 *         msg.isRuaResponse -> handleRuaResponse(msg)
 *     }
 * }
 * ```
 */
class DiaMessage private constructor(internal val handle: Long) : AutoCloseable {
    companion object {
        /**
         * Deserialize a protocol message from bytes.
         *
         * @param data Serialized message bytes
         * @return DiaMessage instance
         * @throws IllegalStateException if parsing fails
         */
        fun parse(data: ByteArray): DiaMessage {
            val handle = LibDia.messageDeserialize(data)
            if (handle == 0L) throw IllegalStateException("Failed to parse message")
            return DiaMessage(handle)
        }
    }

    /** Get the message type (LibDia.MSG_* constant). */
    val type: Int get() = LibDia.messageGetType(handle)

    /** Get sender ID from the message. */
    val senderId: String get() = LibDia.messageGetSenderId(handle)

    /** Get topic from the message. */
    val topic: String get() = LibDia.messageGetTopic(handle)

    /** Returns true if this is an AKE request message. */
    val isAkeRequest: Boolean get() = type == LibDia.MSG_AKE_REQUEST

    /** Returns true if this is an AKE response message. */
    val isAkeResponse: Boolean get() = type == LibDia.MSG_AKE_RESPONSE

    /** Returns true if this is an AKE complete message. */
    val isAkeComplete: Boolean get() = type == LibDia.MSG_AKE_COMPLETE

    /** Returns true if this is a RUA request message. */
    val isRuaRequest: Boolean get() = type == LibDia.MSG_RUA_REQUEST

    /** Returns true if this is a RUA response message. */
    val isRuaResponse: Boolean get() = type == LibDia.MSG_RUA_RESPONSE

    /** Returns true if this is a heartbeat message. */
    val isHeartbeat: Boolean get() = type == LibDia.MSG_HEARTBEAT

    /** Returns true if this is a bye message. */
    val isBye: Boolean get() = type == LibDia.MSG_BYE

    /** Returns true if this is an ODA request message. */
    val isOdaRequest: Boolean get() = type == LibDia.MSG_ODA_REQUEST

    /** Returns true if this is an ODA response message. */
    val isOdaResponse: Boolean get() = type == LibDia.MSG_ODA_RESPONSE

    override fun close() {
        if (handle != 0L) {
            LibDia.messageDestroy(handle)
        }
    }
}

/**
 * Enrollment helper for creating and finalizing enrollment.
 *
 * Example usage:
 * ```kotlin
 * // Client creates enrollment request
 * val (keys, requestData) = Enrollment.createRequest(
 *     phone = "+1234567890",
 *     name = "Alice",
 *     logoUrl = "https://example.com/alice.jpg",
 *     numTickets = 5
 * )
 *
 * // Send requestData to server, receive response
 * val response = sendToServer(requestData)
 *
 * // Finalize enrollment
 * val config = Enrollment.finalize(keys, response, "+1234567890", "Alice", logoUrl)
 * Enrollment.destroyKeys(keys)
 *
 * // Use config for calls
 * config.use { cfg ->
 *     // ...
 * }
 * ```
 */
object Enrollment {
    /**
     * Result of creating an enrollment request.
     *
     * @property keysHandle Enrollment keys handle (8 bytes) - keep for finalization
     * @property requestData Serialized enrollment request to send to server
     */
    data class EnrollmentRequest(
        val keysHandle: ByteArray,
        val requestData: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as EnrollmentRequest
            return keysHandle.contentEquals(other.keysHandle) && 
                   requestData.contentEquals(other.requestData)
        }
        override fun hashCode(): Int = 
            31 * keysHandle.contentHashCode() + requestData.contentHashCode()
    }

    /**
     * Create an enrollment request with all necessary keys.
     *
     * @param phone Phone number to enroll
     * @param name Display name
     * @param logoUrl Logo URL (optional)
     * @param numTickets Number of tickets to request (typically 1-10)
     * @return Pair of keys handle and serialized request
     */
    fun createRequest(
        phone: String,
        name: String,
        logoUrl: String? = null,
        numTickets: Int = 5
    ): EnrollmentRequest {
        val result = LibDia.enrollmentCreateRequest(phone, name, logoUrl, numTickets)
        return EnrollmentRequest(keysHandle = result[0], requestData = result[1])
    }

    /**
     * Finalize enrollment using the server response.
     *
     * @param keysHandle Enrollment keys from createRequest
     * @param response Server response bytes
     * @param phone Phone number (same as in request)
     * @param name Display name (same as in request)
     * @param logoUrl Logo URL (same as in request)
     * @return DiaConfig ready for use in calls
     * @throws IllegalStateException if finalization fails
     */
    fun finalize(
        keysHandle: ByteArray,
        response: ByteArray,
        phone: String,
        name: String,
        logoUrl: String? = null
    ): DiaConfig {
        val configHandle = LibDia.enrollmentFinalize(keysHandle, response, phone, name, logoUrl)
        if (configHandle == 0L) throw IllegalStateException("Failed to finalize enrollment")
        // Use reflection to create DiaConfig with private constructor
        val constructor = DiaConfig::class.java.getDeclaredConstructor(Long::class.javaPrimitiveType)
        constructor.isAccessible = true
        return constructor.newInstance(configHandle)
    }

    /**
     * Free enrollment keys handle. Call this after finalize() to clean up.
     *
     * @param keysHandle Enrollment keys handle to destroy
     */
    fun destroyKeys(keysHandle: ByteArray) {
        LibDia.enrollmentKeysDestroy(keysHandle)
    }
}
