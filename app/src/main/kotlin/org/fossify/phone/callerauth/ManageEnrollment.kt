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
import org.fossify.phone.BuildConfig
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
        numTickets: Int = 5
    ) = withContext(Dispatchers.IO) {
        Log.d(TAG, "▶ Starting enrollment for $phoneNumber")
        
        try {
            // Step 1: Create enrollment request using LibDia v2
            Log.d(TAG, "Creating enrollment request...")
            val enrollmentRequest = DiaEnrollment.createRequest(
                phone = phoneNumber,
                name = displayName,
                logoUrl = logoUrl,
                numTickets = numTickets
            )
            Log.d(TAG, "✓ Enrollment request created (${enrollmentRequest.requestData.size} bytes)")
            
            // Step 2: Wrap in protobuf for gRPC transport
            val protoRequest = Enrollment.EnrollmentRequest.newBuilder()
                .setDiaRequest(ByteString.copyFrom(enrollmentRequest.requestData))
                .build()
            
            // Step 3: Call enrollment server via gRPC
            Log.d(TAG, "Calling enrollment server at ${BuildConfig.ES_HOST}:${BuildConfig.ES_PORT}...")
            val response = callServer(protoRequest)
            Log.d(TAG, "✓ Server responded (${response.diaResponse.size()} bytes)")
            
            // Step 4: Finalize enrollment with server response
            Log.d(TAG, "Finalizing enrollment...")
            val config = DiaEnrollment.finalize(
                keysHandle = enrollmentRequest.keysHandle,
                response = response.diaResponse.toByteArray(),
                phone = phoneNumber,
                name = displayName,
                logoUrl = logoUrl
            )
            Log.d(TAG, "✓ Enrollment finalized")
            
            // Step 5: Serialize and save config
            val envString = config.toEnv()
            Storage.saveDiaConfig(envString)
            Log.d(TAG, "✓ Config saved to storage")
            
            // Step 6: Clean up temporary keys
            DiaEnrollment.destroyKeys(enrollmentRequest.keysHandle)
            Log.d(TAG, "✓ Temporary keys destroyed")
            
            // Close config resource
            config.close()
            
            Log.d(TAG, "✅ Enrollment complete for $phoneNumber")
            
        } catch (e: Exception) {
            Log.e(TAG, "❌ Enrollment failed for $phoneNumber", e)
            throw e
        }
    }

    /**
     * Calls the enrollment server via gRPC.
     */
    private fun callServer(req: Enrollment.EnrollmentRequest): Enrollment.EnrollmentResponse {
        val channel = ManagedChannelBuilder
            .forAddress(BuildConfig.ES_HOST, BuildConfig.ES_PORT)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(10, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ Sending enrollment request to server...")
            val resp = stub.enrollSubscriber(req)
            Log.d(TAG, "✔️ Received enrollment response")
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
