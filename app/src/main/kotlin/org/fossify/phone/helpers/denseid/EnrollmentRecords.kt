package org.fossify.phone.helpers.denseid

import com.google.protobuf.Timestamp

private const val delimiter = "||"

data class DisplayInfo(
    val phoneNumber: String,
    val name: String,
    val logoUrl: String
) {
    override fun toString(): String {
        return "$phoneNumber$delimiter$name$delimiter$logoUrl"
    }

    companion object {
        fun fromString(str: String): DisplayInfo {
            val parts = str.split(delimiter)
            return DisplayInfo(parts[0], parts[1], parts[2])
        }
    }
}

data class MiscInfo(val nBio: Int, val nonce: String) {
    override fun toString(): String {
        return "$nBio$delimiter$nonce"
    }
    companion object {
        fun fromString(str: String): MiscInfo {
            val parts = str.split(delimiter)
            return MiscInfo(parts[0].toInt(), parts[1])
        }
    }
}

data class Credential(
    val eId: String,
    val eExp: Timestamp,
    val ra1Sig: Signature,
    val ra2Sig: Signature
) {
    override fun toString(): String {
        val exp = Signing.encodeToHex(eExp.toByteArray())
        return "$eId$delimiter$exp$delimiter$ra1Sig$delimiter$ra2Sig"
    }

    companion object {
        fun fromString(str: String): Credential {
            val parts = str.split(delimiter)
            val exp = Signing.decodeHex(parts[1])
            val ra1Sig = Signature(parts[2])
            val ra2Sig = Signature(parts[3])
            return Credential(
                parts[0],
                Timestamp.parseFrom(exp),
                ra1Sig, ra2Sig
            )
        }
    }
}
