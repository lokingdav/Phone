package org.fossify.phone.callerauth

import android.util.Log
import kotlinx.coroutines.*

/**
 * OobController manages the out-of-band relay channel for a call.
 * Handles heartbeat messages to keep the channel alive and provides
 * non-blocking message sending for authentication protocol.
 */
class OobController(
    private val relayHost: String,
    private val relayPort: Int,
    initialTopic: String,
    ticket: ByteArray?,
    private val senderID: String,
    private val scope: CoroutineScope,
    useTls: Boolean = true
) {
    companion object {
        private const val TAG = "CallAuth-OobController"
        private const val HEARTBEAT_INTERVAL_MS = 30_000L // 30 seconds
        private val HEARTBEAT_PAYLOAD = byteArrayOf(0x00) // Minimal heartbeat marker
    }

    private val client = RelayClient(relayHost, relayPort, useTls)
    private val session = RelaySession(client, initialTopic, ticket, senderID)
    
    private var heartbeatJob: Job? = null
    private var messageCallback: ((ByteArray) -> Unit)? = null

    /**
     * Starts the OOB channel with message handler.
     * Automatically subscribes to the relay topic.
     */
    fun start(onMessage: (ByteArray) -> Unit) {
        Log.d(TAG, "Starting OOB controller")
        messageCallback = onMessage
        
        session.start(scope) { payload ->
            // Filter out our own heartbeats
            if (payload.contentEquals(HEARTBEAT_PAYLOAD)) {
                Log.v(TAG, "Received heartbeat echo (ignored)")
            } else {
                onMessage(payload)
            }
        }
    }

    /**
     * Starts sending periodic heartbeat messages to keep the channel alive.
     */
    fun startHeartbeat() {
        if (heartbeatJob?.isActive == true) {
            Log.w(TAG, "Heartbeat already running")
            return
        }
        
        Log.d(TAG, "Starting heartbeat (interval: ${HEARTBEAT_INTERVAL_MS}ms)")
        heartbeatJob = scope.launch {
            while (isActive) {
                try {
                    session.send(HEARTBEAT_PAYLOAD)
                    Log.v(TAG, "Sent heartbeat")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to send heartbeat: ${e.message}")
                }
                delay(HEARTBEAT_INTERVAL_MS)
            }
        }
    }

    /**
     * Stops the heartbeat timer.
     */
    fun stopHeartbeat() {
        heartbeatJob?.cancel()
        heartbeatJob = null
        Log.d(TAG, "Heartbeat stopped")
    }

    /**
     * Sends a message through the OOB channel.
     * Non-blocking: queues the message for sending.
     */
    suspend fun send(payload: ByteArray) {
        session.send(payload)
    }

    /**
     * Sends a message to a specific topic.
     */
    suspend fun sendToTopic(topic: String, payload: ByteArray, ticket: ByteArray? = null) {
        session.sendToTopic(topic, payload, ticket)
    }

    /**
     * Swaps to a new topic with optional first message.
     * Used for protocol flows like topic rotation during rekeying.
     */
    suspend fun swapToTopic(newTopic: String, firstMessage: ByteArray? = null, ticket: ByteArray? = null) {
        Log.d(TAG, "Swapping to topic: $newTopic")
        session.swapToTopic(newTopic, firstMessage, ticket)
    }

    /**
     * Subscribes to a new topic (with replay) and optionally sends a message.
     */
    suspend fun subscribeToNewTopic(newTopic: String, piggybackMessage: ByteArray? = null, ticket: ByteArray? = null) {
        Log.d(TAG, "Subscribing to new topic: $newTopic")
        session.subscribeToNewTopic(newTopic, piggybackMessage, ticket)
    }

    /**
     * Closes the OOB channel and cleans up resources.
     */
    suspend fun close() {
        Log.d(TAG, "Closing OOB controller")
        stopHeartbeat()
        session.close()
        client.shutdown()
    }
}
