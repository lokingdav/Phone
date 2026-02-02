package org.fossify.phone.callerauth

import android.util.Log
import io.grpc.ConnectivityState
import io.grpc.ManagedChannel
import io.grpc.Status
import io.grpc.okhttp.OkHttpChannelBuilder
import denseid.relay.v1.RelayServiceGrpcKt
import java.util.concurrent.TimeUnit

/**
 * Singleton pool that reuses gRPC channels to avoid cold-start overhead.
 */
object RelayChannelPool {
    private const val TAG = "CallAuth-RelayChannelPool"
    
    @Volatile
    private var cachedChannel: ManagedChannel? = null
    private var cachedHost: String? = null
    private var cachedPort: Int? = null
    private var cachedTls: Boolean? = null
    
    @Synchronized
    fun getChannel(host: String, port: Int, useTls: Boolean): ManagedChannel {
        val existing = cachedChannel
        
        // Reuse if same config and channel is usable
        if (existing != null && 
            cachedHost == host && 
            cachedPort == port && 
            cachedTls == useTls &&
            !existing.isShutdown && 
            !existing.isTerminated) {
            
            val state = existing.getState(false)
            if (state != ConnectivityState.SHUTDOWN && state != ConnectivityState.TRANSIENT_FAILURE) {
                Log.d(TAG, "Reusing cached channel (state=$state)")
                return existing
            }
            Log.d(TAG, "Cached channel unusable (state=$state), creating new")
        }
        
        // Shutdown old channel if exists
        existing?.let {
            try {
                it.shutdownNow()
            } catch (ignored: Throwable) {}
        }
        
        val t0 = System.currentTimeMillis()
        val newChannel = OkHttpChannelBuilder.forAddress(host, port)
            .apply {
                if (useTls) useTransportSecurity() else usePlaintext()
                keepAliveTime(30, TimeUnit.SECONDS)
                keepAliveTimeout(10, TimeUnit.SECONDS)
                keepAliveWithoutCalls(true)
            }
            .build()
        Log.d(TAG, "TIMING: new channel build took ${System.currentTimeMillis() - t0}ms (host=$host:$port tls=$useTls)")
        
        cachedChannel = newChannel
        cachedHost = host
        cachedPort = port
        cachedTls = useTls
        
        return newChannel
    }
    
    @Synchronized
    fun shutdown() {
        cachedChannel?.let {
            try {
                it.shutdownNow()
                it.awaitTermination(3, TimeUnit.SECONDS)
            } catch (ignored: Throwable) {}
        }
        cachedChannel = null
        cachedHost = null
        cachedPort = null
        cachedTls = null
    }
    
    /**
     * Pre-warms the gRPC channel by creating it and initiating TCP connection.
     * Call this at app startup to eliminate cold-start latency on first call.
     * This is non-blocking - the actual TCP handshake happens in background.
     */
    fun warmup(host: String, port: Int, useTls: Boolean) {
        val t0 = System.currentTimeMillis()
        val channel = getChannel(host, port, useTls)
        // Trigger connection by requesting state with connect=true
        // This initiates TCP handshake in background without blocking
        channel.getState(true)
        Log.d(TAG, "TIMING: warmup initiated in ${System.currentTimeMillis() - t0}ms (host=$host:$port)")
    }
}

class RelayClient(
    host: String,
    port: Int,
    useTls: Boolean = true
) {
    companion object {
        private const val TAG = "CallAuth-RelayClient"
        
        fun isTransient(t: Throwable): Boolean {
            val s = Status.fromThrowable(t).code
            return s == Status.Code.UNAVAILABLE ||
                s == Status.Code.CANCELLED ||
                s == Status.Code.DEADLINE_EXCEEDED
        }
    }

    private val channel: ManagedChannel = RelayChannelPool.getChannel(host, port, useTls)

    val stub: RelayServiceGrpcKt.RelayServiceCoroutineStub =
        RelayServiceGrpcKt.RelayServiceCoroutineStub(channel)

    suspend fun shutdown() {
        // Don't shutdown pooled channel - it will be reused
        // RelayChannelPool.shutdown() should be called on app exit if needed
    }
}
