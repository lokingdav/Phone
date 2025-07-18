package org.fossify.phone.denseid

import java.security.MessageDigest

object Utilities {
    private const val HASH_ALG = "SHA-256"

    fun hash(encoded: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(HASH_ALG)
        md.update(encoded)
        return md.digest()
    }

    fun hash(str: String): ByteArray = hash(str.toByteArray(Charsets.UTF_8))
}
