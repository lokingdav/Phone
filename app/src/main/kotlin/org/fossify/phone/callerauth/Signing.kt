package org.fossify.phone.callerauth

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec


object Signing {
    private const val ALGORITHM = "Ed25519"
    private const val PROVIDER  = "BC"
    private const val TAG = "DenseID::Signing"

    init {
        Security.removeProvider(PROVIDER)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    /** Generate a fresh Ed25519 keypair. */
    fun regSigKeygen(): KeyPair =
        KeyPairGenerator.getInstance(ALGORITHM, PROVIDER).generateKeyPair()

    /** Sign raw message bytes. */
    fun regSigSign(privateKey: PrivateKey, message: ByteArray): ByteArray {
        val sig = Signature.getInstance(ALGORITHM, PROVIDER)
        sig.initSign(privateKey)
        sig.update(message)
        return sig.sign()
    }

    fun regSigVerify(publicKey: PublicKey, signature: ByteArray, message: ByteArray): Boolean {
        val verifier = Signature.getInstance(ALGORITHM, PROVIDER)
        verifier.initVerify(publicKey)
        verifier.update(message)
        return verifier.verify(signature)
    }

    /**
     * Decode a DER-encoded X.509 SubjectPublicKeyInfo (SPKI) blob
     * back into a PublicKey (Bouncy-Castle’s BCEdDSAPublicKey under the hood).
     */
    fun decodePublicKey(encoded: ByteArray): PublicKey {
        val spec = X509EncodedKeySpec(encoded)
        return KeyFactory
            .getInstance(ALGORITHM, PROVIDER)
            .generatePublic(spec)
    }

    /**
     * Decode a DER-encoded PKCS#8 PrivateKeyInfo blob
     * back into a PrivateKey (Bouncy-Castle’s BCEdDSAPrivateKey under the hood).
     */
    fun decodePrivateKey(pkcs8Der: ByteArray): PrivateKey {
        val spec = PKCS8EncodedKeySpec(pkcs8Der)
        return KeyFactory
            .getInstance(ALGORITHM, PROVIDER)
            .generatePrivate(spec)
    }

    /** Encode to hex. */
    fun encodeToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    /** Decode from hex. */
    fun decodeHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}
