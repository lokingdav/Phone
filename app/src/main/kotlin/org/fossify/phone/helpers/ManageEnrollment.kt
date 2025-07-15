package org.fossify.phone.helpers

import android.util.Log
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import org.fossify.phone.BuildConfig
import java.util.UUID

/**
 * Handles key generation, request building, parallel gRPC calls,
 * result gathering and consolidated logging.
 */
object ManageEnrollment {
    private const val TAG = "ManageEnrollment"

    /**
     * Generates a signing keypair, sends parallel enrollment requests to two servers,
     * waits for both to complete, and logs results together.
     */
    suspend fun enroll(
        phoneNumber: String,
        displayName: String,
        logoUrl: String
    ) = coroutineScope {
        // 1) Generate signing keys
        val keys = Signing.regSigKeygen()
        val publicKeyHex = Signing.exportPublicKeyToHexString(keys.public)

        // 2) Build the DisplayInformation message
        val iden = Enrollment.DisplayInformation.newBuilder()
            .setName(displayName)
            .setLogoUrl(logoUrl)
            .build()

        // 3) Build the EnrollmentRequest
        val req = Enrollment.EnrollmentRequest.newBuilder()
            .setTn(phoneNumber)
            .addPublicKeys(publicKeyHex)
            .setIden(iden)
            .setNBio(0)
            .addAllAuthSigs(emptyList())
            .setNonce(UUID.randomUUID().toString())
            .build()

        // 4) Fire two parallel RPC calls and collect EnrollmentResult for each
        val results = listOf(
            async { callServer(BuildConfig.DENSEID_ES1_HOST, BuildConfig.DENSEID_ES1_PORT, req, "ES1") },
            async { callServer(BuildConfig.DENSEID_ES2_HOST, BuildConfig.DENSEID_ES2_PORT, req, "ES2") }
        ).awaitAll()

        // 5) Consolidated logging
        val allSuccess = results.all { it.success }
        if (allSuccess) {
            Log.d(TAG, "All enrollments succeeded")
        } else {
            Log.e(TAG, "Some enrollments failed")
        }
        results.forEach { res ->
            if (res.success) {
                Log.d(TAG, "[${res.label}] ✓ eid=${res.eid}, exp=${res.exp}, usk=${res.usk}, sigma=${res.sigma}")
            } else {
                Log.e(TAG, "[${res.label}] ✗ error=${res.error}")
            }
        }
    }

    private data class EnrollmentResult(
        val label: String,
        val success: Boolean,
        val eid: String? = null,
        val exp: com.google.protobuf.Timestamp? = null,
        val usk: String? = null,
        val sigma: String? = null,
        val error: String? = null
    )

    private fun callServer(
        host: String,
        port: Int,
        req: Enrollment.EnrollmentRequest,
        label: String
    ): EnrollmentResult {
        val channel = ManagedChannelBuilder
            .forAddress(host, port)
            .usePlaintext()
            .build()
        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)

        return try {
            val resp = stub.enrollSubscriber(req)
            EnrollmentResult(
                label   = label,
                success = true,
                eid     = resp.eid,
                exp     = resp.exp,
                usk     = resp.usk,
                sigma   = resp.sigma
            )
        } catch (e: StatusRuntimeException) {
            EnrollmentResult(
                label   = label,
                success = false,
                error   = e.status.toString()
            )
        } finally {
            channel.shutdownNow()
        }
    }
}
