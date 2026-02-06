package org.fossify.phone.callerauth

import android.util.Log
import com.google.protobuf.ByteString
import denseid.relay.v1.Relay
import io.github.lokingdav.libdia.LibDia
import io.grpc.Status
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.IOException
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * RelaySession manages a bidirectional tunnel to the relay server.
 * Handles automatic reconnection, topic management, and non-blocking message sending.
 */
class RelaySession(
    private val client: RelayClient,
    initialTopic: String,
    private val ticket: ByteArray,
    private val senderID: String = UUID.randomUUID().toString()
) {
    companion object {
        private const val TAG = "CallAuth-RelaySession"
        private val RETRY_BACKOFF_MS = longArrayOf(0L, 500L, 1000L, 2000L, 5000L)

        private const val MAC_TOKEN_PREIMAGE_LEN = 32
    }

    // Current active topic (mutable - changes with SWAP/subscribe)
    private val topicMutex = Mutex()
    private var currentTopic = initialTopic

    // Lifecycle management
    private val closed = AtomicBoolean(false)
    private var tunnelJob: Job? = null  // Child job for tunnel loop - cancelling this won't affect parent scope
    
    // Message callback
    private var onMessageCallback: ((ByteArray) -> Unit)? = null

    // Outbound request queue (buffered channel for non-blocking sends)
    private val sendQueue = Channel<Relay.RelayRequest>(capacity = 256)

    // Signals when connection is established and initial SUBSCRIBE has been sent
    private val connectedDeferred = CompletableDeferred<Unit>()

    /**
     * Starts the session with the given message handler.
     * Launches tunnel loop and begins receiving messages.
     */
    fun start(scope: CoroutineScope, onMessage: (ByteArray) -> Unit) {
        if (closed.get()) {
            Log.w(TAG, "Cannot start - session already closed")
            return
        }
        
        onMessageCallback = onMessage
        
        // Launch tunnel as a child job - cancelling tunnelJob won't cancel the parent scope
        tunnelJob = scope.launch(Dispatchers.IO) {
            tunnelLoop()
        }
    }

    /**
     * Suspends until the connection is established and initial SUBSCRIBE has been sent.
     * Use this to ensure messages are ready to be received before proceeding.
     */
    suspend fun awaitConnected() {
        connectedDeferred.await()
    }

    /**
     * Publishes payload to the current topic.
     * Non-blocking: queues the request for sending.
     */
    suspend fun send(payload: ByteArray) {
        if (closed.get()) {
            Log.w(TAG, "Cannot send - session closed")
            return
        }
        
        if (payload.isEmpty()) {
            Log.w(TAG, "Ignoring empty payload")
            return
        }

        val topic = topicMutex.withLock { currentTopic }
        val macTicket = tryBuildMacTicket(Relay.RelayRequest.Type.PUBLISH, topic, payload, ticket)
        if (macTicket == null) {
            Log.e(TAG, "Cannot send PUBLISH - failed to build MAC ticket")
            return
        }
        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.PUBLISH)
            .setTopic(topic)
            .setPayload(ByteString.copyFrom(payload))
            .setTicket(ByteString.copyFrom(macTicket))
            .build()
        
        enqueue(request)
    }

    /**
     * Publishes payload to a specific topic (with optional ticket).
     */
    suspend fun sendToTopic(topic: String, payload: ByteArray, ticket: ByteArray? = null) {
        if (closed.get() || topic.isEmpty() || payload.isEmpty()) {
            return
        }

        val token = ticket ?: this.ticket
        val macTicket = tryBuildMacTicket(Relay.RelayRequest.Type.PUBLISH, topic, payload, token)
        if (macTicket == null) {
            Log.e(TAG, "Cannot send PUBLISH - failed to build MAC ticket")
            return
        }

        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.PUBLISH)
            .setTopic(topic)
            .setPayload(ByteString.copyFrom(payload))
            .setTicket(ByteString.copyFrom(macTicket))
            .build()
        
        enqueue(request)
    }

    /**
     * Subscribes to a new topic with replay, optionally piggy-backing a publish.
     */
    suspend fun subscribeToNewTopic(newTopic: String, piggybackPayload: ByteArray? = null, ticket: ByteArray) {
        if (closed.get() || newTopic.isEmpty()) {
            return
        }

        val payloadBytes = piggybackPayload ?: ByteArray(0)
        val macTicket = tryBuildMacTicket(Relay.RelayRequest.Type.SUBSCRIBE, newTopic, payloadBytes, ticket)
        if (macTicket == null) {
            Log.e(TAG, "Cannot send SUBSCRIBE - failed to build MAC ticket")
            return
        }

        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.SUBSCRIBE)
            .setTopic(newTopic)
            .apply {
                piggybackPayload?.let { setPayload(ByteString.copyFrom(it)) }
                setTicket(ByteString.copyFrom(macTicket))
            }
            .build()
        
        // Update local topic optimistically
        topicMutex.withLock { currentTopic = newTopic }
        enqueue(request)
    }

    /**
     * Closes the session, stopping all coroutines and cleaning up resources.
     */
    fun close() {
        if (closed.getAndSet(true)) {
            return
        }
        
        Log.d(TAG, "Closing session")
        sendQueue.close()
        tunnelJob?.cancel()  // Only cancel the tunnel job, not the parent scope
        tunnelJob = null
    }

    // ===== Internal Implementation =====

    /**
     * Main tunnel loop: manages connection lifecycle and auto-reconnect.
     */
    private suspend fun tunnelLoop() = coroutineScope {
        var backoffIndex = 0
        
        while (!closed.get() && isActive) {
            try {
                val t0 = System.currentTimeMillis()
                Log.d(TAG, "Opening tunnel to relay server...")
                
                // Create the bidirectional stream
                val requestFlow = flow {
                    Log.d(TAG, "TIMING: flow started (gRPC connected) at +${System.currentTimeMillis() - t0}ms")
                    
                    // First, send SUBSCRIBE to current topic (with replay)
                    val topic = topicMutex.withLock { currentTopic }

                    val macTicket = tryBuildMacTicket(Relay.RelayRequest.Type.SUBSCRIBE, topic, ByteArray(0), ticket)
                    if (macTicket == null) {
                        throw IllegalStateException("failed to build MAC ticket for initial SUBSCRIBE")
                    }

                    val subscribeRequest = Relay.RelayRequest.newBuilder()
                        .setSenderId(senderID)
                        .setType(Relay.RelayRequest.Type.SUBSCRIBE)
                        .setTopic(topic)
                        .setTicket(ByteString.copyFrom(macTicket))
                        .build()
                    
                    emit(subscribeRequest)
                    Log.d(TAG, "TIMING: SUBSCRIBE emitted at +${System.currentTimeMillis() - t0}ms")
                    
                    // Signal that we're connected and initial SUBSCRIBE has been sent
                    connectedDeferred.complete(Unit)
                    
                    // Then pump queued requests
                    sendQueue.receiveAsFlow().collect { emit(it) }
                }

                // Start receiving responses
                client.stub.tunnel(requestFlow).collect { response ->
                    val recvTime = System.currentTimeMillis()
                    when (response.type) {
                        Relay.RelayResponse.Type.EVENT -> {
                            val payload = response.payload.toByteArray()
                            Log.d(TAG, "TIMING: EVENT received at +${recvTime - t0}ms on topic ${response.topic} (${payload.size} bytes)")
                            onMessageCallback?.invoke(payload)
                            backoffIndex = 0 // Reset backoff on successful message
                        }
                        
                        Relay.RelayResponse.Type.ERROR -> {
                            Log.w(TAG, "Relay ERROR on topic ${response.topic}: code=${response.code} msg=${response.message}")
                            // Don't disconnect on error - server keeps stream open
                        }
                        
                        else -> {
                            Log.w(TAG, "Unknown response type: ${response.type}")
                        }
                    }
                }
                
                // Stream ended normally (EOF)
                Log.d(TAG, "Tunnel stream ended (EOF), reconnecting...")
                
            } catch (e: Exception) {
                when {
                    closed.get() -> {
                        Log.d(TAG, "Session closed, exiting tunnel loop")
                        return@coroutineScope
                    }
                    
                    e is CancellationException -> {
                        Log.d(TAG, "Tunnel loop cancelled")
                        return@coroutineScope
                    }
                    
                    RelayClient.isTransient(e) -> {
                        Log.w(TAG, "Transient error, will retry: ${e.message}")
                    }
                    
                    else -> {
                        Log.e(TAG, "Non-transient error in tunnel: ${e.message}", e)
                        // Still retry for robustness
                    }
                }
            }
            
            // Backoff before reconnecting
            if (!closed.get() && isActive) {
                val delayMs = RETRY_BACKOFF_MS[backoffIndex.coerceAtMost(RETRY_BACKOFF_MS.lastIndex)]
                if (delayMs > 0) {
                    Log.d(TAG, "Waiting ${delayMs}ms before reconnect...")
                    delay(delayMs)
                }
                backoffIndex++
            }
        }
        
        Log.d(TAG, "Tunnel loop exited")
    }

    /**
     * Enqueues a request for sending. Non-blocking.
     */
    private suspend fun enqueue(request: Relay.RelayRequest) {
        try {
            sendQueue.send(request)
        } catch (e: Exception) {
            if (!closed.get()) {
                Log.e(TAG, "Failed to enqueue request: ${e.message}")
            }
        }
    }

    private fun macDataForReq(type: Relay.RelayRequest.Type, topic: String, payload: ByteArray): ByteArray {
        val topicBytes = topic.toByteArray(Charsets.UTF_8)
        val data = ByteArray(1 + topicBytes.size + payload.size)
        data[0] = type.number.toByte()
        System.arraycopy(topicBytes, 0, data, 1, topicBytes.size)
        System.arraycopy(payload, 0, data, 1 + topicBytes.size, payload.size)
        return data
    }

    private fun tryBuildMacTicket(
        type: Relay.RelayRequest.Type,
        topic: String,
        payload: ByteArray,
        token: ByteArray,
    ): ByteArray? {
        if (token.size < MAC_TOKEN_PREIMAGE_LEN) {
            Log.e(TAG, "Token too short for MAC ticket: len=${token.size}")
            return null
        }
        return try {
            val data = macDataForReq(type, topic, payload)
            val mac = LibDia.messageCreateMac(token, data)
            if (mac.size != 32) {
                Log.w(TAG, "Unexpected MAC length: ${mac.size}")
            }
            val preimage = token.copyOfRange(0, MAC_TOKEN_PREIMAGE_LEN)
            ByteArray(preimage.size + mac.size).apply {
                System.arraycopy(preimage, 0, this, 0, preimage.size)
                System.arraycopy(mac, 0, this, preimage.size, mac.size)
            }
        } catch (e: Throwable) {
            Log.e(TAG, "Failed to build MAC ticket: ${e.message}")
            null
        }
    }
}

