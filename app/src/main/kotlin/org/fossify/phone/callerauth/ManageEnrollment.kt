package org.fossify.phone.callerauth

import android.util.Log
import com.google.protobuf.ByteString
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.github.lokingdav.libdia.Enrollment as DiaEnrollment
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.fossify.phone.App
import java.util.concurrent.TimeUnit

/**
 * Handles enrollment flow using LibDia v2 API
 */
object ManageEnrollment {
    private const val TAG = "CallAuth-ManageEnrollment"

    /**
     * Enrolls a new subscriber using LibDia v2 enrollment protocol.
     * 
     * @param phoneNumber E.164 format phone number
     * @param displayName Display name for the subscriber
     * @param logoUrl URL to subscriber's logo/avatar
     * @param numTickets Number of access tickets to request (default: 5)
     */
    suspend fun enroll(
        phoneNumber: String,
        displayName: String,
        logoUrl: String,
        numTickets: Int = 5,
        otpProvider: suspend (fallbackOtp: String?) -> String = { fallbackOtp ->
            fallbackOtp ?: throw IllegalStateException("OTP required but no provider available")
        }
    ) = withContext(Dispatchers.IO) {
        Log.d(TAG, "▶ Starting enrollment for $phoneNumber")
        var keysHandle: ByteArray? = null

        try {
            // Step 1: Create enrollment request using LibDia v2
            Log.d(TAG, "Creating enrollment request...")
            val enrollmentRequest = DiaEnrollment.createRequest(
                phone = phoneNumber,
                name = displayName,
                logoUrl = logoUrl,
                numTokens = numTickets
            )
            keysHandle = enrollmentRequest.keysHandle
            Log.d(TAG, "✓ Enrollment request created (${enrollmentRequest.requestData.size} bytes)")
            
            // Step 2: Wrap in protobuf for gRPC transport
            val protoRequest = Enrollment.EnrollmentRequest.newBuilder()
                .setDiaRequest(ByteString.copyFrom(enrollmentRequest.requestData))
                .build()
            
            // Step 3: Start enrollment and obtain OTP.
            Log.d(TAG, "Starting enrollment with server...")
            val startResponse = startEnrollment(protoRequest)
            Log.d(TAG, "✓ StartEnrollment responded")

            val otpCode = startResponse.otpCode
                .takeIf { it.isNotBlank() }
                ?: otpProvider(null)
            Log.d(TAG, "✓ OTP acquired")

            // Step 4: Complete enrollment with computed challenge.
            val challenge = DiaEnrollment.computeChallenge(enrollmentRequest.requestData, otpCode)
            Log.d(TAG, "✓ OTP challenge computed")

            val response = completeEnrollment(challenge)
            Log.d(TAG, "✓ CompleteEnrollment responded (${response.diaResponse.size()} bytes)")
            
            // Step 5: Finalize enrollment with server response
            Log.d(TAG, "Finalizing enrollment...")
            val config = DiaEnrollment.finalize(
                keysHandle = enrollmentRequest.keysHandle,
                response = response.diaResponse.toByteArray(),
                phone = phoneNumber,
                name = displayName,
                logoUrl = logoUrl
            )
            Log.d(TAG, "✓ Enrollment finalized")
            
            // Step 6: Serialize and save config
            val envString = config.toEnv()
            Storage.saveDiaConfig(envString)
            Storage.saveEnrolledPhone(phoneNumber)
            Log.d(TAG, "✓ Config saved to storage")
            
            // Step 7: Reload App.diaConfig so it's immediately available
            App.reloadDiaConfig()
            Log.d(TAG, "✓ App.diaConfig reloaded")
            
            // Close config resource
            config.close()
            
            Log.d(TAG, "✅ Enrollment complete for $phoneNumber")
            
        } catch (e: Exception) {
            Log.e(TAG, "❌ Enrollment failed for $phoneNumber", e)
            throw e
        } finally {
            keysHandle?.let {
                runCatching { DiaEnrollment.destroyKeys(it) }
                    .onSuccess { Log.d(TAG, "✓ Temporary keys destroyed") }
                    .onFailure { destroyError -> Log.w(TAG, "Failed to destroy temporary keys", destroyError) }
            }
        }
    }

    /**
     * Calls the enrollment server via gRPC.
     */
    private fun startEnrollment(req: Enrollment.EnrollmentRequest): Enrollment.StartEnrollmentResponse {
        val esHost = Storage.getEffectiveEsHost()
        val esPort = Storage.getEffectiveEsPort()
        val channel = ManagedChannelBuilder
            .forAddress(esHost, esPort)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(10, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ Sending StartEnrollment request to server...")
            val resp = stub.startEnrollment(req)
            Log.d(TAG, "✔️ Received StartEnrollment response")
            return resp
        } catch (e: StatusRuntimeException) {
            Log.e(TAG, "⚠️ RPC failed: ${e.status}", e)
            throw e
        } finally {
            channel.shutdownNow()
            Log.d(TAG, "↩ gRPC channel closed")
        }
    }

    private fun completeEnrollment(challenge: String): Enrollment.EnrollmentResponse {
        val esHost = Storage.getEffectiveEsHost()
        val esPort = Storage.getEffectiveEsPort()
        val channel = ManagedChannelBuilder
            .forAddress(esHost, esPort)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(10, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ Sending CompleteEnrollment request to server...")
            val resp = stub.completeEnrollment(
                Enrollment.CompleteEnrollmentRequest.newBuilder()
                    .setC(challenge)
                    .build()
            )
            Log.d(TAG, "✔️ Received CompleteEnrollment response")
            return resp
        } catch (e: StatusRuntimeException) {
            Log.e(TAG, "⚠️ RPC failed: ${e.status}", e)
            throw e
        } finally {
            channel.shutdownNow()
            Log.d(TAG, "↩ gRPC channel closed")
        }
    }
}
