package org.fossify.phone.denseid

import android.util.Log
import io.github.denseidentity.bbsgroupsig.BBSGS
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Security
import java.security.Signature
import java.security.SignatureException
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

    /**
     * Initialize the pairing operation for BBS group signatures.
     */
    fun initGroupSignatures() {
        BBSGS.bbs04InitPairing()
    }

    /**
     * Sign a message under the group public key (gpk) with the user secret key (usk).
     *
     * @throws java.security.SignatureException if the underlying native call fails
     */
    @Throws(SignatureException::class)
    fun grpSigSign(gpk: ByteArray, usk: ByteArray, msg: ByteArray): ByteArray = try {
        BBSGS.bbs04Sign(gpk, usk, msg)
    } catch (e: Exception) {
        throw SignatureException("grpSigSign failed", e)
    }

    /**
     * Verify a signature on a message under the group public key (gpk).
     * Returns false if verification fails or if an error occurs.
     */
    fun grpSigVerify(gpk: ByteArray, sig: ByteArray, msg: ByteArray): Boolean = try {
        BBSGS.bbs04Verify(gpk, sig, msg)
    } catch (_: Exception) {
        false
    }

    /**
     * Verify user secret key under the group public key (gpk).
     * Returns false if verification fails or if an error occurs.
     */
    fun grpSigVerifyUsk(gpk: ByteArray, usk: ByteArray): Boolean = try {
//        Log.d(TAG, "gpk: ${encodeToHex(gpk)}")
//        Log.d(TAG, "usk: ${encodeToHex(usk)}")
        val res = BBSGS.bbs04VerifyUsk(gpk, usk)
//        Log.d(TAG, "grpSigVerifyUsk: $res")
        res
    } catch (e: Exception) {
//        Log.d(TAG, "grpSigVerifyUsk failed: ${e.message}")
        false
    }
}
