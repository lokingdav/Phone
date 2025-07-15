// src/main/java/org/fossify/phone/helpers/ManageEnrollment.kt
package org.fossify.phone.helpers

import android.util.Log
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.coroutineScope
import org.fossify.phone.BuildConfig
import java.util.UUID
import java.util.concurrent.TimeUnit

/**
 * Handles key generation, request marshaling, signing over the serialized proto,
 * sequential gRPC calls, result gathering and consolidated logging.
 */
object ManageEnrollment {
    private const val TAG = "DenseID-ManageEnrollment"

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
        val publicKeyHex = Signing.exportPublicKeyToHexString(keys.public)
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
            .addPublicKeys(publicKeyHex)
            .setIden(iden)
            .setNBio(0)
            .addAllAuthSigs(emptyList())
            .setNonce(nonce)
            .build()

        // 4) Sign the exact protobuf bytes
        val toSign = unsigned.toByteArray()
        val signatureHex = Signing.encodeToHex(
            Signing.regSigSign(keys.private, toSign)
        )
        Log.d(TAG, "✍️ Signed proto bytes, signature=$signatureHex")

        // 5) Build the final signed request
        val req = unsigned.toBuilder()
            .addAuthSigs(signatureHex)
            .build()
        Log.d(TAG, "📨 Built signed EnrollmentRequest")

        // 6) Sequential calls
        Log.d(TAG, "⚡ Calling ES1")
        val res1 = callServer(BuildConfig.DENSEID_ES1_HOST, BuildConfig.DENSEID_ES1_PORT, req, "ES1")

        Log.d(TAG, "⚡ Calling ES2")
        val res2 = callServer(BuildConfig.DENSEID_ES2_HOST, BuildConfig.DENSEID_ES2_PORT, req, "ES2")

        // 7) Consolidated logging
        Log.d(TAG, "✅ Both calls done, now logging results")
        listOf(res1, res2).forEach { r ->
            if (r.success) {
                Log.d(TAG, "[${r.label}] ✓ eid=${r.eid}")
            } else {
                Log.e(TAG, "[${r.label}] ✗ error=${r.error}")
            }
        }
    }

    private data class EnrollmentResult(
        val label: String,
        val success: Boolean,
        val eid: String? = null,
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
