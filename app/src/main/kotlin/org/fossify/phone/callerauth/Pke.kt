package org.fossify.phone.callerauth

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.util.encoders.Hex
import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * PKE keypair for public key encryption.
 */
data class PkeKeyPair(val private: ByteArray, val public: ByteArray) {
    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pk", Signing.encodeToHex(public))
            put("sk", Signing.encodeToHex(private))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): PkeKeyPair {
            return PkeKeyPair(
                Signing.decodeHex(data.getString("sk")),
                Signing.decodeHex(data.getString("pk"))
            )
        }
    }
}

/**
 * ECIES-style Public Key Encryption using X25519 and AES-256-GCM.
 * Compatible with the Go implementation using curve25519 + HKDF-SHA256 + AES-GCM.
 *
 * Wire format: ephemeralPublic (32) || nonce (12) || ciphertext + GCM tag (16)
 */
object Pke {
    private const val X25519_KEY_SIZE = 32
    private const val AES_KEY_SIZE = 32
    private const val AES_NONCE_SIZE = 12
    private const val GCM_TAG_BITS = 128

    private val secureRandom = SecureRandom()

    /**
     * Generates a new X25519 keypair for PKE.
     * @return Pair of (privateKey, publicKey) where both are 32-byte arrays.
     */
    fun keygen(): Pair<ByteArray, ByteArray> {
        val privateKeyParams = X25519PrivateKeyParameters(secureRandom)
        val publicKeyParams = privateKeyParams.generatePublicKey()

        val privateKey = ByteArray(X25519_KEY_SIZE)
        val publicKey = ByteArray(X25519_KEY_SIZE)

        privateKeyParams.encode(privateKey, 0)
        publicKeyParams.encode(publicKey, 0)

        return Pair(privateKey, publicKey)
    }

    /**
     * Encrypts plaintext using ECIES with X25519 and AES-256-GCM.
     * @param publicKey 32-byte X25519 public key of the recipient.
     * @param plaintext The data to encrypt (must not be empty).
     * @return Encrypted data: ephemeralPublic (32) || nonce (12) || ciphertext + tag.
     */
    fun encrypt(publicKey: ByteArray, plaintext: ByteArray): ByteArray {
        require(publicKey.size == X25519_KEY_SIZE) {
            "Invalid public key size: expected $X25519_KEY_SIZE, got ${publicKey.size}"
        }
        require(plaintext.isNotEmpty()) {
            "Plaintext cannot be empty"
        }

        // Generate ephemeral keypair
        val ephemeralPrivateParams = X25519PrivateKeyParameters(secureRandom)
        val ephemeralPublicParams = ephemeralPrivateParams.generatePublicKey()

        val ephemeralPublic = ByteArray(X25519_KEY_SIZE)
        ephemeralPublicParams.encode(ephemeralPublic, 0)

        // Compute shared secret using ECDH
        val recipientPublicParams = X25519PublicKeyParameters(publicKey, 0)
        val sharedSecret = computeSharedSecret(ephemeralPrivateParams, recipientPublicParams)

        // Derive AES key using HKDF
        val aesKey = deriveKey(sharedSecret, ephemeralPublic, publicKey)

        // Generate random nonce
        val nonce = ByteArray(AES_NONCE_SIZE)
        secureRandom.nextBytes(nonce)

        // Encrypt with AES-256-GCM (using ephemeralPublic as AAD)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(aesKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(ephemeralPublic)
        val ciphertext = cipher.doFinal(plaintext)

        // Output format: ephemeralPublic (32) || nonce (12) || ciphertext+tag
        val result = ByteArray(X25519_KEY_SIZE + AES_NONCE_SIZE + ciphertext.size)
        System.arraycopy(ephemeralPublic, 0, result, 0, X25519_KEY_SIZE)
        System.arraycopy(nonce, 0, result, X25519_KEY_SIZE, AES_NONCE_SIZE)
        System.arraycopy(ciphertext, 0, result, X25519_KEY_SIZE + AES_NONCE_SIZE, ciphertext.size)

        return result
    }

    /**
     * Decrypts ciphertext using ECIES with X25519 and AES-256-GCM.
     * @param privateKey 32-byte X25519 private key.
     * @param ciphertext The encrypted data (ephemeralPublic || nonce || ciphertext+tag).
     * @return Decrypted plaintext.
     */
    fun decrypt(privateKey: ByteArray, ciphertext: ByteArray): ByteArray {
        require(privateKey.size == X25519_KEY_SIZE) {
            "Invalid private key size: expected $X25519_KEY_SIZE, got ${privateKey.size}"
        }

        val minCiphertextSize = X25519_KEY_SIZE + AES_NONCE_SIZE + 16 // 16 is GCM tag size
        require(ciphertext.size >= minCiphertextSize) {
            "Ciphertext too short: minimum $minCiphertextSize bytes required"
        }

        // Parse ciphertext components
        val ephemeralPublic = ciphertext.copyOfRange(0, X25519_KEY_SIZE)
        val nonce = ciphertext.copyOfRange(X25519_KEY_SIZE, X25519_KEY_SIZE + AES_NONCE_SIZE)
        val encryptedData = ciphertext.copyOfRange(X25519_KEY_SIZE + AES_NONCE_SIZE, ciphertext.size)

        // Reconstruct our keys
        val myPrivateParams = X25519PrivateKeyParameters(privateKey, 0)
        val myPublicParams = myPrivateParams.generatePublicKey()
        val myPublicKey = ByteArray(X25519_KEY_SIZE)
        myPublicParams.encode(myPublicKey, 0)

        // Compute shared secret using ECDH
        val ephemeralPublicParams = X25519PublicKeyParameters(ephemeralPublic, 0)
        val sharedSecret = computeSharedSecret(myPrivateParams, ephemeralPublicParams)

        // Derive AES key using HKDF
        val aesKey = deriveKey(sharedSecret, ephemeralPublic, myPublicKey)

        // Decrypt with AES-256-GCM
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(aesKey, "AES")
        val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(ephemeralPublic)

        return cipher.doFinal(encryptedData)
    }

    /**
     * Computes the X25519 shared secret (ECDH).
     */
    private fun computeSharedSecret(
        privateKey: X25519PrivateKeyParameters,
        publicKey: X25519PublicKeyParameters
    ): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(privateKey)
        val sharedSecret = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(publicKey, sharedSecret, 0)
        return sharedSecret
    }

    /**
     * Derives an AES key from the shared secret using HKDF-SHA256.
     * Info = ephemeralPublic || recipientPublic (matches Go implementation).
     */
    private fun deriveKey(
        sharedSecret: ByteArray,
        ephemeralPublic: ByteArray,
        recipientPublic: ByteArray
    ): ByteArray {
        // Info: ephemeral_pk || recipient_pk
        val info = ByteArray(ephemeralPublic.size + recipientPublic.size)
        System.arraycopy(ephemeralPublic, 0, info, 0, ephemeralPublic.size)
        System.arraycopy(recipientPublic, 0, info, ephemeralPublic.size, recipientPublic.size)

        // HKDF-SHA256 with no salt
        val hkdf = HKDFBytesGenerator(org.bouncycastle.crypto.digests.SHA256Digest())
        hkdf.init(HKDFParameters(sharedSecret, null, info))

        val key = ByteArray(AES_KEY_SIZE)
        hkdf.generateBytes(key, 0, AES_KEY_SIZE)

        return key
    }
}
