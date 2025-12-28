package org.fossify.phone.callerauth.protocol

import org.fossify.phone.callerauth.protocol.Signing
import org.json.JSONObject
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey

data class MyKeyPair(
    val private: PrivateKey,
    val public: PublicKey,
) {
    constructor(keypair: KeyPair): this(keypair.private, keypair.public);

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
                Signing.decodePrivateKey(sk),
                Signing.decodePublicKey(pk)
            )
        }
    }
}
