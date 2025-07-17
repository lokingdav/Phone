package org.fossify.phone.helpers.denseid

import android.util.Log
import org.fossify.phone.helpers.DenseIdentityStore
import org.json.JSONObject

private const val delimiter = "."

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
        val rawPk = Signing.toRawPublicKey(keyPair.public)
        val attributes: List<String> = listOf(
            display.phoneNumber,
            display.name, display.logoUrl,
            misc.nBio.toString(),
            misc.nonce.toString(),
            Signing.encodeToHex(rawPk)
        )
        return attributes
    }

    fun save() {
        val enrollmentJson = JSONObject().apply {
            put(KeyLabel.DISPLAY_INFO.code, display)
            put(KeyLabel.MISC_INFO.code,misc)
            put(KeyLabel.ENROLLED_CRED.code,enrollmentCred)
            put(KeyLabel.KEY_PAIR.code,keyPair)
            put(KeyLabel.GROUP_KEYS.code,groupKeys)
        }
        val data = enrollmentJson.toString()
        Log.d("Dense Identity", "Saving $data")
        DenseIdentityStore.putString(KeyLabel.DID.code, data)
    }

    companion object {
        fun load(): UserState? {
            val dataStr = DenseIdentityStore.getString(KeyLabel.DID.code)
            if (dataStr.isNullOrBlank()) {
                return null
            }

            val data = JSONObject(dataStr)
            val displayInfo = data.getString(KeyLabel.DISPLAY_INFO.code)
            val miscInfo = data.getString(KeyLabel.MISC_INFO.code)
            val enrollmentCred = data.getString(KeyLabel.ENROLLED_CRED.code)
            val keyPair = data.getString(KeyLabel.KEY_PAIR.code)
            val groupKeys = data.getString(KeyLabel.GROUP_KEYS.code)

            return UserState(
                display=DisplayInfo.fromString(displayInfo),
                misc=MiscInfo.fromString(miscInfo),
                enrollmentCred=Credential.fromString(enrollmentCred),
                keyPair=MyKeyPair.fromString(keyPair),
                groupKeys=GroupKeys.fromString(groupKeys)
            )
        }
    }
}
