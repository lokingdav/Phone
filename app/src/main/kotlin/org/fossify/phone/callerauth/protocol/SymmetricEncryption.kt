package org.fossify.phone.callerauth.protocol

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Symmetric encryption using AES-256-GCM.
 * Wire format: nonce (12 bytes) || ciphertext || tag (16 bytes)
 */
object SymmetricEncryption {
    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 12
    private const val TAG_BITS = 128

    private val secureRandom = SecureRandom()

    /**
     * Encrypts plaintext using AES-256-GCM.
     * @param secretKey 32-byte secret key
     * @param plaintext data to encrypt
     * @return nonce || ciphertext || tag
     */
    fun encrypt(secretKey: ByteArray, plaintext: ByteArray): ByteArray {
        require(secretKey.size == KEY_SIZE) {
            "Secret key must be $KEY_SIZE bytes, got ${secretKey.size}"
        }

        val nonce = ByteArray(NONCE_SIZE)
        secureRandom.nextBytes(nonce)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(secretKey, "AES")
        val gcmSpec = GCMParameterSpec(TAG_BITS, nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

        val ciphertext = cipher.doFinal(plaintext)

        // Output: nonce || ciphertext (includes GCM tag)
        return nonce + ciphertext
    }

    /**
     * Decrypts ciphertext using AES-256-GCM.
     * @param secretKey 32-byte secret key
     * @param ciphertext nonce || ciphertext || tag
     * @return decrypted plaintext
     */
    fun decrypt(secretKey: ByteArray, ciphertext: ByteArray): ByteArray {
        require(secretKey.size == KEY_SIZE) {
            "Secret key must be $KEY_SIZE bytes, got ${secretKey.size}"
        }
        require(ciphertext.size >= NONCE_SIZE + 16) {
            "Ciphertext too short"
        }

        val nonce = ciphertext.copyOfRange(0, NONCE_SIZE)
        val encryptedData = ciphertext.copyOfRange(NONCE_SIZE, ciphertext.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(secretKey, "AES")
        val gcmSpec = GCMParameterSpec(TAG_BITS, nonce)
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

        return cipher.doFinal(encryptedData)
    }
}
