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

    /**
     * Encodes bytes to hexadecimal string.
     */
    fun encodeToHex(data: ByteArray): String {
        return data.joinToString("") { "%02x".format(it) }
    }

    /**
     * Decodes hexadecimal string to bytes.
     */
    fun decodeHex(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }

    /**
     * Concatenates multiple byte arrays into one.
     */
    fun concatBytes(vararg chunks: ByteArray): ByteArray {
        val total = chunks.sumOf { it.size }
        val out = ByteArray(total)
        var offset = 0
        for (chunk in chunks) {
            System.arraycopy(chunk, 0, out, offset, chunk.size)
            offset += chunk.size
        }
        return out
    }
}
