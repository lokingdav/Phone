package org.fossify.phone.callerauth

import android.util.Log
import com.google.protobuf.ByteString
import denseid.relay.v1.Relay
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
    private val ticket: ByteArray?,
    private val senderID: String = UUID.randomUUID().toString()
) {
    companion object {
        private const val TAG = "CallAuth-RelaySession"
        private val RETRY_BACKOFF_MS = longArrayOf(0L, 500L, 1000L, 2000L, 5000L)
    }

    // Current active topic (mutable - changes with SWAP/subscribe)
    private val topicMutex = Mutex()
    private var currentTopic = initialTopic

    // Lifecycle management
    private val closed = AtomicBoolean(false)
    private var sessionScope: CoroutineScope? = null
    private var writerJob: Job? = null
    
    // Message callback
    private var onMessageCallback: ((ByteArray) -> Unit)? = null

    // Outbound request queue (buffered channel for non-blocking sends)
    private val sendQueue = Channel<Relay.RelayRequest>(capacity = 256)

    /**
     * Starts the session with the given message handler.
     * Launches tunnel loop and begins receiving messages.
     */
    fun start(scope: CoroutineScope, onMessage: (ByteArray) -> Unit) {
        if (closed.get()) {
            Log.w(TAG, "Cannot start - session already closed")
            return
        }
        
        sessionScope = scope
        onMessageCallback = onMessage
        
        scope.launch(Dispatchers.IO) {
            tunnelLoop()
        }
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
        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.PUBLISH)
            .setTopic(topic)
            .setPayload(ByteString.copyFrom(payload))
            .apply { ticket?.let { setTicket(ByteString.copyFrom(it)) } }
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

        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.PUBLISH)
            .setTopic(topic)
            .setPayload(ByteString.copyFrom(payload))
            .apply { ticket?.let { setTicket(ByteString.copyFrom(it)) } }
            .build()
        
        enqueue(request)
    }

    /**
     * Swaps from current topic to a new topic with optional first message.
     * Used for protocol flows like Bob swapping from Alice's topic to Bob's topic.
     */
    suspend fun swapToTopic(toTopic: String, firstMessage: ByteArray? = null, ticket: ByteArray? = null) {
        if (closed.get() || toTopic.isEmpty()) {
            return
        }

        val fromTopic = topicMutex.withLock { currentTopic }
        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.SWAP)
            .setTopic(fromTopic)
            .setToTopic(toTopic)
            .apply { 
                firstMessage?.let { setPayload(ByteString.copyFrom(it)) }
                ticket?.let { setTicket(ByteString.copyFrom(it)) }
            }
            .build()
        
        // Update local topic optimistically
        topicMutex.withLock { currentTopic = toTopic }
        enqueue(request)
    }

    /**
     * Subscribes to a new topic with replay, optionally piggy-backing a publish.
     */
    suspend fun subscribeToNewTopic(newTopic: String, piggybackPayload: ByteArray? = null, ticket: ByteArray? = null) {
        if (closed.get() || newTopic.isEmpty()) {
            return
        }

        val request = Relay.RelayRequest.newBuilder()
            .setSenderId(senderID)
            .setType(Relay.RelayRequest.Type.SUBSCRIBE)
            .setTopic(newTopic)
            .apply {
                piggybackPayload?.let { setPayload(ByteString.copyFrom(it)) }
                ticket?.let { setTicket(ByteString.copyFrom(it)) }
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
        writerJob?.cancel()
        sessionScope?.cancel()
    }

    // ===== Internal Implementation =====

    /**
     * Main tunnel loop: manages connection lifecycle and auto-reconnect.
     */
    private suspend fun tunnelLoop() {
        var backoffIndex = 0
        
        while (!closed.get() && sessionScope?.isActive == true) {
            try {
                Log.d(TAG, "Opening tunnel...")
                
                // Create the bidirectional stream
                val requestFlow = flow {
                    // First, send SUBSCRIBE to current topic (with replay)
                    val topic = topicMutex.withLock { currentTopic }
                    val subscribeRequest = Relay.RelayRequest.newBuilder()
                        .setSenderId(senderID)
                        .setType(Relay.RelayRequest.Type.SUBSCRIBE)
                        .setTopic(topic)
                        .build()
                    
                    emit(subscribeRequest)
                    Log.d(TAG, "Sent initial SUBSCRIBE to topic: $topic")
                    
                    // Then pump queued requests
                    sendQueue.receiveAsFlow().collect { emit(it) }
                }

                // Start receiving responses
                client.stub.tunnel(requestFlow).collect { response ->
                    when (response.type) {
                        Relay.RelayResponse.Type.EVENT -> {
                            val payload = response.payload.toByteArray()
                            Log.d(TAG, "Received EVENT on topic ${response.topic} (${payload.size} bytes)")
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
                        return
                    }
                    
                    e is CancellationException -> {
                        Log.d(TAG, "Tunnel loop cancelled")
                        return
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
            if (!closed.get()) {
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
}

