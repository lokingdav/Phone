package org.fossify.phone.callerauth

import android.util.Log
import com.google.protobuf.ByteString
import denseid.enrollment.v1.Enrollment
import denseid.enrollment.v1.EnrollmentServiceGrpc
import io.grpc.ManagedChannelBuilder
import io.grpc.StatusRuntimeException
import kotlinx.coroutines.coroutineScope
import org.fossify.phone.BuildConfig
import java.util.concurrent.TimeUnit

/**
 * Handles enrollment flow - NEEDS MIGRATION TO LIBDIA V2
 * TODO: Replace with io.github.lokingdav.libdia.Enrollment API
 */
object ManageEnrollment {
    private const val TAG = "CallAuth-ManageEnrollment"

    /**
     * TODO: Migrate to LibDia v2 enrollment API
     * See: io.github.lokingdav.libdia.Enrollment.createRequest() and finalize()
     */
    suspend fun enroll(
        phoneNumber: String,
        displayName: String,
        logoUrl: String
    ): Nothing = coroutineScope {
        Log.d(TAG, "▶ enroll() start for $phoneNumber")
        
        // TODO: Replace with LibDia v2:
        // val (keys, requestData) = Enrollment.createRequest(phoneNumber, displayName, logoUrl, numTickets = 5)
        // Send requestData to server
        // val response = callServer(...)
        // val config = Enrollment.finalize(keys, response, phoneNumber, displayName, logoUrl)
        // Enrollment.destroyKeys(keys)
        // Save config for future calls
        
        Log.e(TAG, "❌ Enrollment not yet migrated to LibDia v2 - implement using new API")
        throw NotImplementedError("Migrate to LibDia v2 Enrollment API")
    }

    private fun callServer(req: Enrollment.EnrollmentRequest): Enrollment.EnrollmentResponse {
        val channel = ManagedChannelBuilder
            .forAddress(BuildConfig.ES_HOST, BuildConfig.ES_PORT)
            .usePlaintext()
            .build()

        val stub = EnrollmentServiceGrpc.newBlockingStub(channel)
            .withDeadlineAfter(5, TimeUnit.SECONDS)

        try {
            Log.d(TAG, "⏳ Sending RPC")
            val resp = stub.enrollSubscriber(req)
            Log.d(TAG, "✔️ Got eid=${resp.eid}")
            return resp
        } catch (e: StatusRuntimeException) {
            Log.e(TAG, "⚠️ RPC failed: ${e.status}", e)
            throw e
        } finally {
            channel.shutdownNow()
            Log.d(TAG, "↩ Channel shutdown")
        }
    }
}
