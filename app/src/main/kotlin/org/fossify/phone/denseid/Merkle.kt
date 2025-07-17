import java.security.MessageDigest
import java.util.ArrayList
import java.io.ByteArrayOutputStream
import java.io.ObjectOutputStream
import java.io.ByteArrayInputStream
import java.io.ObjectInputStream
import java.io.Serializable
import java.util.Base64

/**
 * A clean, self-contained utility for building and verifying SHA-256 Merkle trees.
 *
 * - Domain-separated leaf vs. node hashing
 * - Constant-time root comparison
 * - Typed proof with direction flags
 * - Built-in Java serialization (byte-array & Base64) for network transport
 */
object Merkle {
    private const val LEAF_PREFIX: Byte = 0x00
    private const val NODE_PREFIX: Byte = 0x01

    private fun newDigest(): MessageDigest = MessageDigest.getInstance("SHA-256")

    /**
     * Compute Merkle root from a list of UTF-8 strings.
     */
    fun createRoot(items: List<String>): ByteArray {
        require(items.isNotEmpty()) { "Item list cannot be empty." }
        val leaves = items.map { leafHash(it.toByteArray(Charsets.UTF_8)) }
        return buildTree(leaves)
    }

    /**
     * Generate an inclusion proof for the given item string.
     */
    fun generateProof(items: List<String>, item: String): MerkleProof? {
        val index = items.indexOf(item)
        if (index == -1) return null

        var level = items.map { leafHash(it.toByteArray(Charsets.UTF_8)) }
        val hashes = mutableListOf<ByteArray>()
        val directions = mutableListOf<Boolean>()
        var idx = index

        while (level.size > 1) {
            val pairIndex = if (idx % 2 == 0) idx + 1 else idx - 1
            val siblingHash = if (pairIndex < level.size) level[pairIndex] else level[idx]
            val isLeft = pairIndex < idx
            hashes += siblingHash
            directions += isLeft

            level = nextLevel(level)
            idx /= 2
        }
        return MerkleProof(hashes, directions)
    }

    /**
     * Verify an inclusion proof against a given root.
     */
    fun verifyProof(root: ByteArray, item: String, proof: MerkleProof): Boolean {
        var computed = leafHash(item.toByteArray(Charsets.UTF_8))
        for ((siblingHash, isLeft) in proof.nodes()) {
            computed = if (isLeft) nodeHash(siblingHash, computed) else nodeHash(computed, siblingHash)
        }
        return MessageDigest.isEqual(root, computed)
    }

    private fun leafHash(data: ByteArray): ByteArray =
        newDigest().digest(byteArrayOf(LEAF_PREFIX) + data)

    private fun nodeHash(left: ByteArray, right: ByteArray): ByteArray =
        newDigest().digest(byteArrayOf(NODE_PREFIX) + left + right)

    private fun buildTree(level: List<ByteArray>): ByteArray =
        if (level.size == 1) level.first() else buildTree(nextLevel(level))

    private fun nextLevel(nodes: List<ByteArray>): List<ByteArray> {
        val out = ArrayList<ByteArray>(nodes.size / 2 + 1)
        for (i in nodes.indices step 2) {
            val left = nodes[i]
            val right = if (i + 1 < nodes.size) nodes[i + 1] else left
            out += nodeHash(left, right)
        }
        return out
    }

    /**
     * A typed, Serializable Merkle inclusion proof.
     * Provides byte-array and Base64 serialization for transport.
     */
    data class MerkleProof(
        val hashes: List<ByteArray>,
        val directions: List<Boolean>
    ) : Serializable {
        /** Sequence of (hash, isLeftSibling) */
        fun nodes(): Sequence<Pair<ByteArray, Boolean>> =
            hashes.asSequence().zip(directions.asSequence())

        /** Serialize to a byte array via Java's built-in serialization */
        fun toByteArray(): ByteArray = ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { it.writeObject(this) }
            bos.toByteArray()
        }

        /** Serialize to Base64 string for JSON or gRPC string field */
        fun toBase64(): String = Base64.getEncoder().encodeToString(toByteArray())

        companion object {
            /** Deserialize from a byte array */
            fun fromByteArray(bytes: ByteArray): MerkleProof =
                ByteArrayInputStream(bytes).use { bis ->
                    ObjectInputStream(bis).use { ois ->
                        @Suppress("UNCHECKED_CAST")
                        ois.readObject() as MerkleProof
                    }
                }

            /** Deserialize from Base64 string */
            fun fromBase64(str: String): MerkleProof =
                fromByteArray(Base64.getDecoder().decode(str))
        }
    }
}
