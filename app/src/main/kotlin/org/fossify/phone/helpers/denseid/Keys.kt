package org.fossify.phone.helpers.denseid

import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

private const val delimiter = "."

data class GroupKeys(val usk: USK, val gpk: GPK) {
    fun verifyUsk(): Boolean {
        return Signing.grpSigVerifyUsk(gpk.encoded, usk.encoded)
    }

    override fun toString(): String {
        return "${usk}${delimiter}${gpk}"
    }

    companion object {
        fun fromString(str: String): GroupKeys {
            val parts = str.split(delimiter)
            return GroupKeys(USK.fromString(parts[0]), GPK.fromString(parts[1]))
        }
    }
}

open class GPK(open val encoded: ByteArray) {
    override fun toString(): String =
        Signing.encodeToHex(encoded)

    companion object {
        /** Parse a GPK (raw bytes) from its hex form. */
        fun fromString(str: String): GPK =
            GPK(Signing.decodeHex(str))
    }
}

data class USK(
    override val encoded: ByteArray
) : GPK(encoded) {
    companion object {
        fun fromString(str: String): USK =
            USK(Signing.decodeHex(str))
    }
}

data class MyKeyPair(
    val public: PublicKey,
    val private: PrivateKey
) {
    constructor(keypair: KeyPair): this(keypair.public, keypair.private);

    override fun toString(): String {
        val pk = Signing.encodeToHex(public.encoded)
        val sk = Signing.encodeToHex(private.encoded)
        return "$pk$delimiter$sk"
    }

    companion object {
        fun fromString(str: String): MyKeyPair {
            val parts = str.split(delimiter)
            val pk = Signing.decodePublicKey(Signing.decodeHex(parts[0]))
            val sk = Signing.decodePrivateKey(Signing.decodeHex(parts[1]))
            return MyKeyPair(pk, sk)
        }
    }
}
