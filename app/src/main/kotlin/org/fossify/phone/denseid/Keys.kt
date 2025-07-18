package org.fossify.phone.denseid

import org.json.JSONObject
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class GPK(val encoded: ByteArray);
data class USK(val encoded: ByteArray);

data class GroupKeys(val usk: USK, val gpk: GPK) {
    fun verifyUsk(): Boolean {
        return Signing.grpSigVerifyUsk(gpk.encoded, usk.encoded)
    }

    fun verifySignature(signature: ByteArray, msg: ByteArray): Boolean {
        return Signing.grpSigVerify(gpk.encoded, signature, msg)
    }

    fun sign(message: ByteArray): ByteArray {
        return Signing.grpSigSign(
            gpk.encoded,
            usk.encoded,
            message
        )
    }

    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("uk", Signing.encodeToHex(usk.encoded))
            put("pk", Signing.encodeToHex(gpk.encoded))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): GroupKeys {
            return GroupKeys(
                USK(Signing.decodeHex(data.getString("uk"))),
                GPK(Signing.decodeHex(data.getString("pk")))
            )
        }
    }
}

data class MyKeyPair(
    val public: PublicKey,
    val private: PrivateKey
) {
    constructor(keypair: KeyPair): this(keypair.public, keypair.private);

    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pk", Signing.encodeToHex(public.encoded))
            put("sk", Signing.encodeToHex(private.encoded))
        }

        return data
    }

    companion object {
        fun fromJson(data: JSONObject): MyKeyPair {
            val pk = Signing.decodeHex(data.getString("pk"))
            val sk = Signing.decodeHex(data.getString("sk"))
            return MyKeyPair(
                Signing.decodePublicKey(pk),
                Signing.decodePrivateKey(sk)
            )
        }
    }
}
