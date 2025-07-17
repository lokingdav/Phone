// src/main/java/org/fossify/phone/helpers/Signing.kt
package org.fossify.phone.helpers

import android.util.Log
import io.github.denseidentity.bbsgroupsig.BBSGS
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
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
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.security.SignatureException

/**
 * Helper for Ed25519 operations:
 * - keygen, sign, verify
 * - raw public/private key import & export (hex + Base64)
 * - hex/Base64 encode-decode
 */
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

    /** Verify signature using raw 32-byte public key bytes. */
    fun regSigVerify(publicKeyBytes: ByteArray, message: ByteArray, signatureBytes: ByteArray): Boolean {
        val spki = SubjectPublicKeyInfo(
            AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
            DERBitString(publicKeyBytes)
        )
        val keySpec = X509EncodedKeySpec(spki.encoded)
        val pubKey = KeyFactory.getInstance(ALGORITHM, PROVIDER).generatePublic(keySpec)

        val verifier = Signature.getInstance(ALGORITHM, PROVIDER)
        verifier.initVerify(pubKey)
        verifier.update(message)
        return verifier.verify(signatureBytes)
    }

    /** Extract and hex-encode the raw 32-byte Ed25519 public key. */
    fun exportPublicKeysToBytes(publicKey: PublicKey): ByteArray {
        val spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(publicKey.encoded))
        return spki.publicKeyData.bytes
    }

    /** Extract and hex-encode the raw Ed25519 private key (seed). */
    fun exportPrivateKeyToBytes(privateKey: PrivateKey): ByteArray {
        val p8 = PrivateKeyInfo.getInstance(ASN1Primitive.fromByteArray(privateKey.encoded))
        val raw = (p8.privateKeyAlgorithm.parameters as? DEROctetString)?.octets
            ?: p8.parsePrivateKey().toASN1Primitive().encoded
        return raw
    }

    /** Import a raw 32-byte public key (hex) back into a PublicKey. */
    fun importPublicKeyFromBytes(raw: ByteArray): PublicKey {
        val spki = SubjectPublicKeyInfo(
            AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
            DERBitString(raw)
        )
        val keySpec = X509EncodedKeySpec(spki.encoded)
        return KeyFactory.getInstance(ALGORITHM, PROVIDER).generatePublic(keySpec)
    }

    /** Import a raw Ed25519 private key (hex seed) back into a PrivateKey. */
    fun importPrivateKeyFromBytes(raw: ByteArray): PrivateKey {
        // wrap raw into PKCS#8 PrivateKeyInfo
        val p8 = PrivateKeyInfo(
            AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
            DEROctetString(raw)
        )
        val keySpec = PKCS8EncodedKeySpec(p8.encoded)
        return KeyFactory.getInstance(ALGORITHM, PROVIDER).generatePrivate(keySpec)
    }

    /** Encode to hex. */
    fun encodeToHex(bytes: ByteArray): String =
        bytes.joinToString("") { "%02x".format(it) }

    /** Decode from hex. */
    fun decodeHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    /** Encode to Base64. */
    fun encodeToBase64(bytes: ByteArray): String =
        Base64.getEncoder().encodeToString(bytes)

    /** Decode from Base64. */
    fun decodeBase64(b64: String): ByteArray =
        Base64.getDecoder().decode(b64)

    /**
     * Initialize the pairing operation for BBS group signatures.
     */
    fun initGroupSignatures() {
        BBSGS.bbs04InitPairing()
    }

    /**
     * Sign a message under the group public key (gpk) with the user secret key (usk).
     *
     * @throws SignatureException if the underlying native call fails
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
        Log.d(TAG, "gpk: ${encodeToHex(gpk)}")
        Log.d(TAG, "usk: ${encodeToHex(usk)}")
        val res = BBSGS.bbs04VerifyUsk(gpk, usk)
        Log.d(TAG, "grpSigVerifyUsk: $res")
        res
    } catch (e: Exception) {
        Log.d(TAG, "grpSigVerifyUsk failed: ${e.message}")
        false
    }

    /**
     * Open (deanonymize) a signature to reveal the signer, using the opening secret key (osk).
     *
     * @throws SignatureException if the underlying native call fails
     */
    @Throws(SignatureException::class)
    fun grpSigOpenSig(gpk: ByteArray, osk: ByteArray, sig: ByteArray): ByteArray = try {
        BBSGS.bbs04Open(gpk, osk, sig)
    } catch (e: Exception) {
        throw SignatureException("grpSigOpenSig failed", e)
    }
}
