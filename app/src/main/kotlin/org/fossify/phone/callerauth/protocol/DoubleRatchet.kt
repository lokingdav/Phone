package org.fossify.phone.callerauth.protocol

import com.google.protobuf.ByteString
import denseid.protocol.v1.Protocol
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.fossify.phone.callerauth.protocol.Signing
import org.json.JSONObject
import java.security.SecureRandom
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.concurrent.withLock

/**
 * Double Ratchet keypair for secure messaging.
 */
data class DrKeyPair(val private: ByteArray, val public: ByteArray) {
    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pk", Signing.encodeToHex(public))
            put("sk", Signing.encodeToHex(private))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): DrKeyPair {
            return DrKeyPair(
                Signing.decodeHex(data.getString("sk")),
                Signing.decodeHex(data.getString("pk"))
            )
        }
    }
}

/**
 * Double Ratchet implementation compatible with status-im/doubleratchet Go library.
 * Uses X25519 for DH, HKDF-SHA256 for KDF, and AES-256-CTR + HMAC-SHA256 for encryption.
 */
object DoubleRatchet {
    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 16  // AES-CTR IV size
    private const val MAC_SIZE = 32    // HMAC-SHA256 output

    private val secureRandom = SecureRandom()

    /**
     * Generates a new X25519 keypair for Double Ratchet.
     * @return Pair of (privateKey, publicKey) where both are 32-byte arrays.
     */
    fun keygen(): Pair<ByteArray, ByteArray> {
        val privateKeyParams = X25519PrivateKeyParameters(secureRandom)
        val publicKeyParams = privateKeyParams.generatePublicKey()

        val privateKey = ByteArray(KEY_SIZE)
        val publicKey = ByteArray(KEY_SIZE)

        privateKeyParams.encode(privateKey, 0)
        publicKeyParams.encode(publicKey, 0)

        return Pair(privateKey, publicKey)
    }

    /**
     * Initializes a Double Ratchet session as the recipient (Bob).
     * The recipient provides their pre-generated DR keypair.
     * Called at the end of AKE finalization.
     *
     * @param sessionId Unique session identifier (used as HKDF info)
     * @param sharedKey 32-byte shared secret from AKE
     * @param drPrivateKey 32-byte X25519 private key
     * @param drPublicKey 32-byte X25519 public key
     */
    fun initAsRecipient(
        sessionId: ByteArray,
        sharedKey: ByteArray,
        drPrivateKey: ByteArray,
        drPublicKey: ByteArray
    ): DrSession {
        require(sharedKey.size == KEY_SIZE) { "Shared key must be 32 bytes" }
        require(drPrivateKey.size == KEY_SIZE) { "DR private key must be 32 bytes" }
        require(drPublicKey.size == KEY_SIZE) { "DR public key must be 32 bytes" }

        val state = DrState(
            sessionId = sessionId.copyOf(),
            rootKey = sharedKey.copyOf(),
            dhKeyPair = DhKeyPair(drPrivateKey.copyOf(), drPublicKey.copyOf()),
            remoteDhPk = null,  // Will be set on first received message
            sendingChainKey = null,
            receivingChainKey = null,
            sendingMessageNumber = 0u,
            receivingMessageNumber = 0u,
            previousChainLength = 0u,
            skippedKeys = mutableMapOf()
        )

        return DrSession(state)
    }

    /**
     * Initializes a Double Ratchet session as the caller (Alice).
     * The caller uses the recipient's DR public key from the AKE exchange.
     * Called at the end of AKE completion.
     *
     * @param sessionId Unique session identifier (used as HKDF info)
     * @param sharedKey 32-byte shared secret from AKE
     * @param remoteDrPk 32-byte X25519 public key of the recipient
     */
    fun initAsCaller(
        sessionId: ByteArray,
        sharedKey: ByteArray,
        remoteDrPk: ByteArray
    ): DrSession {
        require(sharedKey.size == KEY_SIZE) { "Shared key must be 32 bytes" }
        require(remoteDrPk.size == KEY_SIZE) { "Remote DR public key must be 32 bytes" }

        // Generate our first ephemeral DH keypair
        val (dhPrivate, dhPublic) = keygen()

        // Perform initial DH ratchet step
        val dhOutput = dh(dhPrivate, remoteDrPk)
        val (newRootKey, sendingChainKey) = kdfRootKey(sharedKey, dhOutput, sessionId)

        val state = DrState(
            sessionId = sessionId.copyOf(),
            rootKey = newRootKey,
            dhKeyPair = DhKeyPair(dhPrivate, dhPublic),
            remoteDhPk = remoteDrPk.copyOf(),
            sendingChainKey = sendingChainKey,
            receivingChainKey = null,
            sendingMessageNumber = 0u,
            receivingMessageNumber = 0u,
            previousChainLength = 0u,
            skippedKeys = mutableMapOf()
        )

        return DrSession(state)
    }

    /**
     * Encrypts a message using the Double Ratchet session.
     * @return Protocol.DrMessage that can be serialized and sent
     */
    fun encrypt(session: DrSession, plaintext: ByteArray, associatedData: ByteArray): Protocol.DrMessage {
        return session.lock.withLock {
            val state = session.state

            // Derive message key from sending chain
            val (chainKey, messageKey) = kdfChainKey(
                state.sendingChainKey ?: throw IllegalStateException("Sending chain not initialized")
            )
            state.sendingChainKey = chainKey

            // Encrypt the message
            val ciphertext = encryptMessage(messageKey, plaintext, associatedData)

            // Build the header
            val header = Protocol.DrHeader.newBuilder()
                .setDh(ByteString.copyFrom(state.dhKeyPair.publicKey))
                .setN(state.sendingMessageNumber.toInt())
                .setPn(state.previousChainLength.toInt())
                .build()

            state.sendingMessageNumber++

            Protocol.DrMessage.newBuilder()
                .setHeader(header)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .build()
        }
    }

    /**
     * Decrypts a message using the Double Ratchet session.
     */
    fun decrypt(session: DrSession, msg: Protocol.DrMessage, associatedData: ByteArray): ByteArray {
        return session.lock.withLock {
            val state = session.state
            val header = msg.header ?: throw IllegalArgumentException("Message header cannot be null")
            val remoteDh = header.dh.toByteArray()
            val messageNumber = header.n.toUInt()
            val previousChainLength = header.pn.toUInt()

            // Check for skipped message key
            val skippedKey = SkippedKeyId(remoteDh.copyOf(), messageNumber)
            state.skippedKeys[skippedKey]?.let { messageKey ->
                state.skippedKeys.remove(skippedKey)
                return@withLock decryptMessage(messageKey, msg.ciphertext.toByteArray(), associatedData)
            }

            // Check if we need to perform a DH ratchet step
            if (state.remoteDhPk == null || !remoteDh.contentEquals(state.remoteDhPk)) {
                // Skip any remaining messages from the previous receiving chain
                if (state.receivingChainKey != null && state.remoteDhPk != null) {
                    skipMessageKeys(state, previousChainLength)
                }

                // Perform DH ratchet
                dhRatchet(state, remoteDh)
            }

            // Skip any messages we haven't received yet
            skipMessageKeys(state, messageNumber)

            // Derive message key from receiving chain
            val (chainKey, messageKey) = kdfChainKey(
                state.receivingChainKey ?: throw IllegalStateException("Receiving chain not initialized")
            )
            state.receivingChainKey = chainKey
            state.receivingMessageNumber++

            decryptMessage(messageKey, msg.ciphertext.toByteArray(), associatedData)
        }
    }

    // --- Internal Helper Functions ---

    /**
     * Performs X25519 Diffie-Hellman key exchange.
     */
    private fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val privateParams = X25519PrivateKeyParameters(privateKey, 0)
        val publicParams = X25519PublicKeyParameters(publicKey, 0)

        val agreement = X25519Agreement()
        agreement.init(privateParams)
        val sharedSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicParams, sharedSecret, 0)
        return sharedSecret
    }

    /**
     * KDF for root key chain: (RK, DH_out) -> (new_RK, CK)
     * Uses HKDF-SHA256 with session ID as info.
     */
    private fun kdfRootKey(rootKey: ByteArray, dhOutput: ByteArray, sessionId: ByteArray): Pair<ByteArray, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(dhOutput, rootKey, sessionId))

        val output = ByteArray(KEY_SIZE * 2)
        hkdf.generateBytes(output, 0, output.size)

        val newRootKey = output.copyOfRange(0, KEY_SIZE)
        val chainKey = output.copyOfRange(KEY_SIZE, KEY_SIZE * 2)

        return Pair(newRootKey, chainKey)
    }

    /**
     * KDF for symmetric key chain: CK -> (new_CK, MK)
     * Uses HMAC-SHA256 with constants 0x01 and 0x02.
     */
    private fun kdfChainKey(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val newChainKey = hmacSha256(chainKey, byteArrayOf(0x01))
        val messageKey = hmacSha256(chainKey, byteArrayOf(0x02))
        return Pair(newChainKey, messageKey)
    }

    /**
     * HMAC-SHA256.
     */
    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val hmac = HMac(SHA256Digest())
        hmac.init(KeyParameter(key))
        hmac.update(data, 0, data.size)
        val result = ByteArray(hmac.macSize)
        hmac.doFinal(result, 0)
        return result
    }

    /**
     * Encrypts a message using AES-256-CTR + HMAC-SHA256.
     * Format: nonce (16) || ciphertext || mac (32)
     */
    private fun encryptMessage(messageKey: ByteArray, plaintext: ByteArray, associatedData: ByteArray): ByteArray {
        // Derive encryption key and MAC key from message key
        val (encKey, macKey) = deriveMessageKeys(messageKey)

        // Generate random nonce
        val nonce = ByteArray(NONCE_SIZE)
        secureRandom.nextBytes(nonce)

        // Encrypt with AES-256-CTR
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(nonce))
        val ciphertext = cipher.doFinal(plaintext)

        // Compute MAC over AD || nonce || ciphertext
        val macInput = associatedData + nonce + ciphertext
        val mac = hmacSha256(macKey, macInput)

        // Output: nonce || ciphertext || mac
        return nonce + ciphertext + mac
    }

    /**
     * Decrypts a message using AES-256-CTR + HMAC-SHA256.
     */
    private fun decryptMessage(messageKey: ByteArray, encryptedData: ByteArray, associatedData: ByteArray): ByteArray {
        require(encryptedData.size >= NONCE_SIZE + MAC_SIZE) { "Encrypted data too short" }

        // Parse components
        val nonce = encryptedData.copyOfRange(0, NONCE_SIZE)
        val ciphertext = encryptedData.copyOfRange(NONCE_SIZE, encryptedData.size - MAC_SIZE)
        val receivedMac = encryptedData.copyOfRange(encryptedData.size - MAC_SIZE, encryptedData.size)

        // Derive encryption key and MAC key from message key
        val (encKey, macKey) = deriveMessageKeys(messageKey)

        // Verify MAC
        val macInput = associatedData + nonce + ciphertext
        val expectedMac = hmacSha256(macKey, macInput)
        require(receivedMac.contentEquals(expectedMac)) { "MAC verification failed" }

        // Decrypt with AES-256-CTR
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), IvParameterSpec(nonce))
        return cipher.doFinal(ciphertext)
    }

    /**
     * Derives encryption and MAC keys from message key using HKDF.
     */
    private fun deriveMessageKeys(messageKey: ByteArray): Pair<ByteArray, ByteArray> {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(messageKey, null, "MessageKeys".toByteArray()))

        val output = ByteArray(KEY_SIZE * 2)
        hkdf.generateBytes(output, 0, output.size)

        val encKey = output.copyOfRange(0, KEY_SIZE)
        val macKey = output.copyOfRange(KEY_SIZE, KEY_SIZE * 2)

        return Pair(encKey, macKey)
    }

    /**
     * Performs a DH ratchet step when receiving a new remote public key.
     */
    private fun dhRatchet(state: DrState, remoteDh: ByteArray) {
        state.previousChainLength = state.sendingMessageNumber
        state.sendingMessageNumber = 0u
        state.receivingMessageNumber = 0u
        state.remoteDhPk = remoteDh.copyOf()

        // Derive receiving chain key
        val dhOutput1 = dh(state.dhKeyPair.privateKey, remoteDh)
        val (rk1, receivingChainKey) = kdfRootKey(state.rootKey, dhOutput1, state.sessionId)
        state.rootKey = rk1
        state.receivingChainKey = receivingChainKey

        // Generate new DH keypair
        val (newPrivate, newPublic) = keygen()
        state.dhKeyPair = DhKeyPair(newPrivate, newPublic)

        // Derive sending chain key
        val dhOutput2 = dh(newPrivate, remoteDh)
        val (rk2, sendingChainKey) = kdfRootKey(state.rootKey, dhOutput2, state.sessionId)
        state.rootKey = rk2
        state.sendingChainKey = sendingChainKey
    }

    /**
     * Skips message keys up to the given message number, storing them for later.
     */
    private fun skipMessageKeys(state: DrState, until: UInt) {
        val maxSkip = 1000u  // Prevent DoS by limiting skipped messages
        
        if (state.receivingMessageNumber + maxSkip < until) {
            throw IllegalStateException("Too many skipped messages")
        }

        val chainKey = state.receivingChainKey ?: return

        var ck = chainKey
        while (state.receivingMessageNumber < until) {
            val (newCk, messageKey) = kdfChainKey(ck)
            ck = newCk
            
            val keyId = SkippedKeyId(state.remoteDhPk!!.copyOf(), state.receivingMessageNumber)
            state.skippedKeys[keyId] = messageKey
            state.receivingMessageNumber++
        }
        state.receivingChainKey = ck
    }
}

/**
 * X25519 key pair for DH ratchet.
 */
data class DhKeyPair(
    val privateKey: ByteArray,
    val publicKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DhKeyPair) return false
        return privateKey.contentEquals(other.privateKey) && publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int {
        return 31 * privateKey.contentHashCode() + publicKey.contentHashCode()
    }
}

/**
 * Identifier for skipped message keys.
 */
data class SkippedKeyId(
    val dhPublicKey: ByteArray,
    val messageNumber: UInt
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SkippedKeyId) return false
        return dhPublicKey.contentEquals(other.dhPublicKey) && messageNumber == other.messageNumber
    }

    override fun hashCode(): Int {
        return 31 * dhPublicKey.contentHashCode() + messageNumber.hashCode()
    }
}

/**
 * Internal Double Ratchet state.
 */
class DrState(
    val sessionId: ByteArray,
    var rootKey: ByteArray,
    var dhKeyPair: DhKeyPair,
    var remoteDhPk: ByteArray?,
    var sendingChainKey: ByteArray?,
    var receivingChainKey: ByteArray?,
    var sendingMessageNumber: UInt,
    var receivingMessageNumber: UInt,
    var previousChainLength: UInt,
    val skippedKeys: MutableMap<SkippedKeyId, ByteArray>
)

/**
 * Thread-safe Double Ratchet session wrapper.
 */
class DrSession internal constructor(
    internal val state: DrState
) {
    internal val lock = ReentrantLock()
}
