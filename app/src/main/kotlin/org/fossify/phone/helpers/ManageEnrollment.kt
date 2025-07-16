package org.fossify.phone.helpers

import android.util.Log
import com.google.protobuf.ByteString
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.coroutineScope
import org.fossify.phone.BuildConfig
import org.json.JSONObject
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Handles key generation, request marshaling, signing over the serialized proto,
 * sequential gRPC calls, result gathering and consolidated logging.
 */
object ManageEnrollment {
    private const val TAG = "DenseID-ManageEnrollment"
    private const val PREFIX: String = "denseid"

    /**
     * Builds a signed EnrollmentRequest, performs two RPCs in sequence,
     * and logs all results together.
     */
    suspend fun enroll(
        phoneNumber: String,
        displayName: String,
        logoUrl: String
    ) = coroutineScope {
        Log.d(TAG, "▶ enroll() start for $phoneNumber")

        // 1) Generate signing keypair
        val keys = Signing.regSigKeygen()
        val publicKeyBytes = Signing.exportPublicKeysToBytes(keys.public)
        val publicKeyHex = Signing.encodeToHex(publicKeyBytes)
        Log.d(TAG, "🔑 Generated key, pubHex=$publicKeyHex")

        // 2) Build the DisplayInformation message
        val iden = Enrollment.DisplayInformation.newBuilder()
            .setName(displayName)
            .setLogoUrl(logoUrl)
            .build()

        // 3) Build the unsigned EnrollmentRequest
        val nonce = UUID.randomUUID().toString()
        val unsigned = Enrollment.EnrollmentRequest.newBuilder()
            .setTn(phoneNumber)
            .addPublicKeys(ByteString.copyFrom(publicKeyBytes))
            .setIden(iden)
            .setNBio(0)
            .addAllAuthSigs(emptyList())
            .setNonce(nonce)
            .build()

        // 4) Sign the exact protobuf bytes
        val toSign = unsigned.toByteArray()
        val signatureBytes = Signing.regSigSign(keys.private, toSign)
        val signatureHex = Signing.encodeToHex(signatureBytes)
        Log.d(TAG, "✍️ Signed proto bytes, signature=$signatureHex")

        // 5) Build the final signed request
        val req = unsigned.toBuilder()
            .addAuthSigs(ByteString.copyFrom(signatureBytes))
            .build()
        Log.d(TAG, "📨 Built signed EnrollmentRequest")

        // 6) Sequential calls
        Log.d(TAG, "⚡ Calling ES1")
        val res1 = callServer(BuildConfig.DENSEID_ES1_HOST, BuildConfig.DENSEID_ES1_PORT, req, "ES1")

        Log.d(TAG, "⚡ Calling ES2")
        val res2 = callServer(BuildConfig.DENSEID_ES2_HOST, BuildConfig.DENSEID_ES2_PORT, req, "ES2")

        // 7) Finalize
        finalizeEnrollment(
            phoneNumber=phoneNumber,
            displayName=displayName,
            logoUrl=logoUrl,
            publicKeyBytes=publicKeyBytes,
            privateKeyBytes= Signing.exportPrivateKeyToBytes(keys.private),
            records = listOf(res1, res2)
        )
    }

    private fun finalizeEnrollment(
        phoneNumber: String,
        displayName: String,
        logoUrl: String,
        publicKeyBytes: ByteArray,
        privateKeyBytes: ByteArray,
        records: List<EnrollmentResult>
    ) {
        val enrollmentJson = JSONObject().apply {
            put("phoneNumber",    phoneNumber)
            put("displayName",    displayName)
            put("logoUrl",        logoUrl)
            put("publicKeyHex",   Signing.encodeToHex(publicKeyBytes))
            put("privateKeyHex",  Signing.encodeToHex(privateKeyBytes))
            put("eid",            records[0].eid)
            put("sigma1Hex",      Signing.encodeToHex(records[0].sigma ?: ByteArray(0)))
            put("sigma2Hex",      Signing.encodeToHex(records[1].sigma ?: ByteArray(0)))
            put("uskHex",         Signing.encodeToHex(records[0].usk ?: ByteArray(0)))
        }

        val jsonString = enrollmentJson.toString()
        DenseIdentityStore.putString("$PREFIX.enrollmentData", jsonString)

        Log.d(TAG, "✅ Both calls done, now logging results")
        records.forEach { r ->
            if (r.success) {
                Log.d(TAG, "[${r.label}] ✓ eid=${r.eid}")
            } else {
                Log.e(TAG, "[${r.label}] ✗ error=${r.error}")
            }
        }
    }

    fun getEnrollmentRecord() {
        val enrollmentData = DenseIdentityStore.getString("$PREFIX.enrollmentData")
        val enrollmentJson = JSONObject(enrollmentData ?: "{}")
        val eid = enrollmentJson.getString("eid")
        val usk = enrollmentJson.getString("uskHex")
    }

    data class EnrollmentRecords(
        val phoneNumber: String,
        val displayName: String,
        val logoUrl: String,
        val publicKeyBytes: ByteArray,
        val privateKeyBytes: ByteArray,
        val eid: String,
        val usk: ByteArray,
        val gpk: ByteArray,
        val sigma: ByteArray
    )

    private data class EnrollmentResult(
        val label: String,
        val success: Boolean,
        val eid: String? = null,
        val usk: ByteArray? = null,
        val gpk: ByteArray? = null,
        val sigma: ByteArray? = null,
        val error: String? = null
    )

    private fun callServer(
        host: String,
        port: Int,
        req: Enrollment.EnrollmentRequest,
        label: String
    ): EnrollmentResult {
        Log.d(TAG, "↪ callServer($label) → $host:$port")
        val channel = ManagedChannelBuilder
            .forAddress(host, port)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(5, TimeUnit.SECONDS)

        return try {
            Log.d(TAG, "⏳ [$label] sending RPC")
            val resp = stub.enrollSubscriber(req)
            Log.d(TAG, "✔️ [$label] got eid=${resp.eid}")
            EnrollmentResult(label, true, eid = resp.eid)
        } catch (e: StatusRuntimeException) {
            Log.e(TAG, "⚠️ [$label] RPC failed: ${e.status}", e)
            EnrollmentResult(label, false, error = e.status.toString())
        } finally {
            channel.shutdownNow()
            Log.d(TAG, "↩ callServer($label) channel shutdown")
        }
    }
}
