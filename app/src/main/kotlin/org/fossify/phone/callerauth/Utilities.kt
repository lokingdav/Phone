package org.fossify.phone.callerauth

import java.security.MessageDigest

object Utilities {
    private const val HASH_ALG = "SHA-256"

    fun hash(encoded: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(HASH_ALG)
        md.update(encoded)
        return md.digest()
    }

    fun hash(str: String): ByteArray = hash(str.toByteArray(Charsets.UTF_8))

    /**
     * Concatenates all input byte arrays and returns their SHA-256 hash.
     * Matches Go's helpers.HashAll behavior.
     */
    fun hashAll(vararg inputs: ByteArray): ByteArray {
        val md = MessageDigest.getInstance(HASH_ALG)
        for (input in inputs) {
            md.update(input)
        }
        return md.digest()
    }
}
