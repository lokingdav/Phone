package org.fossify.phone.denseid

import android.util.Log
import org.json.JSONObject

private const val TAG = "Dense Identity"

enum class KeyLabel(val code: String) {
    DID("DId"),
    DISPLAY_INFO("DN"),
    MISC_INFO("MI"),
    KEY_PAIR("KP"),
    ENROLLED_CRED("CR"),
    GROUP_KEYS("GK"),
}

data class UserState(
    val display: DisplayInfo,
    val misc: MiscInfo,
    val enrollmentCred: Credential,
    val keyPair: MyKeyPair,
    val groupKeys: GroupKeys
) {
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

    fun save() {
        val enrollmentJson = JSONObject().apply {
            put(KeyLabel.DISPLAY_INFO.code, display.toJson())
            put(KeyLabel.MISC_INFO.code,misc.toJson())
            put(KeyLabel.ENROLLED_CRED.code,enrollmentCred.toJson())
            put(KeyLabel.KEY_PAIR.code,keyPair.toJson())
            put(KeyLabel.GROUP_KEYS.code,groupKeys.toJson())
        }
        val data = enrollmentJson.toString()
        Log.d("Dense Identity", "Saving $data")
        Storage.putString(KeyLabel.DID.code, data)
    }

    companion object {
        fun load(): UserState? {
            val dataStr = Storage.getString(KeyLabel.DID.code)
            if (dataStr.isNullOrBlank()) {
                return null
            }

            val data = JSONObject(dataStr)

            try {
                val state = UserState(
                    display=DisplayInfo.fromJson(data.getJSONObject(KeyLabel.DISPLAY_INFO.code)),
                    misc=MiscInfo.fromJson(data.getJSONObject(KeyLabel.MISC_INFO.code)),
                    enrollmentCred=Credential.fromJson(data.getJSONObject(KeyLabel.ENROLLED_CRED.code)),
                    keyPair=MyKeyPair.fromJson(data.getJSONObject(KeyLabel.KEY_PAIR.code)),
                    groupKeys=GroupKeys.fromJson(data.getJSONObject(KeyLabel.GROUP_KEYS.code))
                )
                return state
            } catch (e: Exception) {
                Log.e(TAG,"Failed to Load $TAG state", e)
            }

            return null
        }
    }
}
