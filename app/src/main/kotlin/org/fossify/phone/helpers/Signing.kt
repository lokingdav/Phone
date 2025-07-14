package org.fossify.phone.helpers

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature

/**
 * A helper object for handling Ed25519 cryptographic operations,
 * including key generation, signing, verification, and key exporting.
 * Also provides utilities for hex encoding and decoding.
 */
object Signing {

    private const val RS_ALGORITHM = "Ed25519"
    private const val PROVIDER = "BC" // Use the Bouncy Castle provider

    init {
        Security.removeProvider(PROVIDER)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    /**
     * Generates a new Ed25519 key pair using the Bouncy Castle provider.
     * This creates an in-memory key pair, not one stored in the Android KeyStore.
     *
     * @return A KeyPair object containing the public and private keys.
     */
    fun regSigKeygen(): KeyPair {
        // FIX: Specify the "BC" provider to avoid using the AndroidKeyStore
        val keyPairGenerator = KeyPairGenerator.getInstance(RS_ALGORITHM, PROVIDER)
        return keyPairGenerator.generateKeyPair()
    }

    /**
     * Signs a given message using a private key.
     *
     * @param privateKey The Ed25519 private key to use for signing.
     * @param message The byte array of the message to be signed.
     * @return A byte array representing the signature.
     */
    fun regSigSign(privateKey: PrivateKey, message: ByteArray): ByteArray {
        val signature = Signature.getInstance(RS_ALGORITHM, PROVIDER)
        signature.initSign(privateKey)
        signature.update(message)
        return signature.sign()
    }

    /**
     * Verifies a signature against a message using a public key.
     *
     * @param publicKey The Ed25519 public key to use for verification.
     * @param message The byte array of the original message.
     * @param signature The byte array of the signature to verify.
     * @return True if the signature is valid, false otherwise.
     */
    fun regSigVerify(publicKey: PublicKey, message: ByteArray, signature: ByteArray): Boolean {
        val verifier = Signature.getInstance(RS_ALGORITHM, PROVIDER)
        verifier.initVerify(publicKey)
        verifier.update(message)
        return verifier.verify(signature)
    }

    /**
     * Exports a public key to its standard X.509 format, encoded as a hex string.
     *
     * @param publicKey The PublicKey to export.
     * @return The key as a hexadecimal string.
     */
    fun exportPublicKeyToHexString(publicKey: PublicKey): String {
        return encodeToString(publicKey.encoded)
    }

    /**
     * Exports a private key to its standard PKCS#8 format, encoded as a hex string.
     *
     * @param privateKey The PrivateKey to export.
     * @return The key as a hexadecimal string.
     */
    fun exportPrivateKeyToHexString(privateKey: PrivateKey): String {
        return encodeToString(privateKey.encoded)
    }

    /**
     * Encodes a byte array into a hexadecimal string.
     *
     * @param bytes The byte array to encode.
     * @return The resulting hexadecimal string.
     */
    fun encodeToString(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    /**
     * Decodes a hexadecimal string into a byte array.
     *
     * @param hexString The hexadecimal string to decode.
     * @return The resulting byte array.
     * @throws IllegalArgumentException if the hexString has an odd length or contains non-hex characters.
     */
    fun decodeString(hexString: String): ByteArray {
        require(hexString.length % 2 == 0) { "Hex string must have an even length" }
        return hexString.chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()
    }
}
