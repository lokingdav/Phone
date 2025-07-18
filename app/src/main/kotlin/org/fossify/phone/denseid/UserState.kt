package org.fossify.phone.denseid

import Merkle
import android.util.Log
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.ObjectInputStream
import java.io.ObjectOutputStream

private const val TAG = "Dense Identity"

enum class KeyLabel(val code: String) {
    DID("DId"),
    DISPLAY_INFO("DN"),
    MISC_INFO("MI"),
    KEY_PAIR("KP"),
    ENROLLED_CRED("CR"),
    GROUP_KEYS("GK"),

    SHARED_STATE("ST")
}

data class SharedState(
    val phoneNumber: String,
    var rootKey: ByteArray,
    var channelKey: ByteArray
) {
    fun toJson(): JSONObject {
        val data = JSONObject().apply {
            put("pn", phoneNumber)
            put("rk", Signing.encodeToHex(rootKey))
            put("ck", Signing.encodeToHex(channelKey))
        }
        return data
    }

    companion object {
        fun fromJson(data: JSONObject): SharedState {
            return SharedState(
                data.getString("pn"),
                Signing.decodeHex(data.getString("rk")),
                Signing.decodeHex(data.getString("ck"))
            )
        }
    }
}

object UserState {
    lateinit var display: DisplayInfo
    lateinit var misc: MiscInfo
    lateinit var enrollmentCred: Credential
    lateinit var keyPair: MyKeyPair
    lateinit var groupKeys: GroupKeys
    lateinit var inclusionProofs: MutableMap<String, Merkle.MerkleProof>

    fun update(
        display: DisplayInfo,
        misc: MiscInfo,
        enrollmentCred: Credential,
        keyPair: MyKeyPair,
        groupKeys: GroupKeys
    ) {
        this.display = display
        this.misc = misc
        this.enrollmentCred = enrollmentCred
        this.keyPair = keyPair
        this.groupKeys = groupKeys
        generateInclusionProofs()
    }

    fun addSharedState(recipient: String, sharedKey: ByteArray): SharedState {
        val state = SharedState(
            recipient,
            sharedKey,
            Utilities.hash(sharedKey + "channelKey".toByteArray())
        )
        Storage.putString(
            "${display.phoneNumber}${recipient}${KeyLabel.SHARED_STATE.code}",
            state.toJson().toString()
        )
        return state
    }

    fun getSharedState(recipient: String): SharedState? {
        val dataStr = Storage.getString(
            "${display.phoneNumber}${recipient}${KeyLabel.SHARED_STATE.code}"
        )
        if (dataStr.isNullOrBlank()) {
            return null
        }
        return SharedState.fromJson(JSONObject(dataStr))
    }

    fun getCommitmentAttributes(): List<String> {
        val attributes: List<String> = listOf(
            display.phoneNumber,
            display.name,
            display.logoUrl,
            misc.nBio.toString(),
            misc.nonce.toString(),
            Signing.encodeToHex(keyPair.public.encoded)
        )
        return attributes
    }

    fun generateInclusionProofs() {
        val attributes = getCommitmentAttributes()
        val pkHex = Signing.encodeToHex(keyPair.public.encoded)
        inclusionProofs = mutableMapOf()
        inclusionProofs[display.phoneNumber] = Merkle.generateProof(attributes, display.phoneNumber)!!
        inclusionProofs[display.name] = Merkle.generateProof(attributes, display.name)!!
        inclusionProofs[display.logoUrl] = Merkle.generateProof(attributes, display.logoUrl)!!
        inclusionProofs[pkHex] = Merkle.generateProof(attributes, pkHex)!!
    }

    fun serializeInclusionProofs(): ByteArray {
        ByteArrayOutputStream().use { bos ->
            ObjectOutputStream(bos).use { oos ->
                oos.writeObject(inclusionProofs)
            }
            return bos.toByteArray()
        }
    }

    fun deserializeInclusionProofs(bytes: ByteArray): MutableMap<String, Merkle.MerkleProof> {
        require(bytes.isNotEmpty()) { "Cannot deserialize empty byte array" }
        ByteArrayInputStream(bytes).use { bis ->
            ObjectInputStream(bis).use { ois ->
                val obj = ois.readObject()
                @Suppress("UNCHECKED_CAST")
                return obj as MutableMap<String, Merkle.MerkleProof>
            }
        }
    }

    fun persist() {
        val data = toJson().toString()
        Log.d("Dense Identity", "Saving $data")
        Storage.putString(KeyLabel.DID.code, data)
    }

    fun toJson(): JSONObject {
        val state = JSONObject().apply {
            put(KeyLabel.DISPLAY_INFO.code, display.toJson())
            put(KeyLabel.MISC_INFO.code,misc.toJson())
            put(KeyLabel.ENROLLED_CRED.code,enrollmentCred.toJson())
            put(KeyLabel.KEY_PAIR.code,keyPair.toJson())
            put(KeyLabel.GROUP_KEYS.code,groupKeys.toJson())
        }
        return state
    }

    fun load() {
        val dataStr = Storage.getString(KeyLabel.DID.code)
        if (dataStr.isNullOrBlank()) {
            return
        }

        val data = JSONObject(dataStr)

        try {
            update(
                display=DisplayInfo.fromJson(data.getJSONObject(KeyLabel.DISPLAY_INFO.code)),
                misc=MiscInfo.fromJson(data.getJSONObject(KeyLabel.MISC_INFO.code)),
                enrollmentCred=Credential.fromJson(data.getJSONObject(KeyLabel.ENROLLED_CRED.code)),
                keyPair=MyKeyPair.fromJson(data.getJSONObject(KeyLabel.KEY_PAIR.code)),
                groupKeys=GroupKeys.fromJson(data.getJSONObject(KeyLabel.GROUP_KEYS.code))
            )
            generateInclusionProofs()
        } catch (e: Exception) {
            Log.e(TAG,"Failed to Load $TAG state", e)
        }
    }
}
