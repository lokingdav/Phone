package org.fossify.phone.metrics

import android.content.Context
import android.telecom.Call
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.fossify.phone.App
import org.fossify.phone.callerauth.Storage
import org.fossify.phone.extensions.config
import java.io.File
import java.io.FileWriter
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue

object MetricsRecorder {
    private const val TAG = "DIA-Metrics"
    private const val FILE_NAME = "denseid_results.csv"

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val fileLock = Any()

    @Volatile
    private var appContext: Context? = null

    private val header = listOf(
        "attempt_id",
        "call_id",
        "self_phone",
        "peer_phone",
        "peer_uri",
        "direction",
        "protocol_enabled",
        "dial_sent_unix_ms",
        "answered_unix_ms",
        "latency_ms",
        "oda_requested_unix_ms",
        "oda_completed_unix_ms",
        "oda_latency_ms",
        "outcome",
        "error"
    )

    data class AttemptContext(
        val attemptId: String,
        val direction: String,
        val protocolEnabled: Boolean,
        val peerPhone: String,
        val peerUri: String,
        val dialSentAtUnixMs: Long,
    ) {
        @Volatile var callId: String = ""
        @Volatile var answeredAtUnixMs: Long = 0L
        @Volatile var answeredEmitted: Boolean = false

        @Volatile var odaRequestedAtUnixMs: Long = 0L
    }

    private val pendingOutgoingByPeer = ConcurrentHashMap<String, ConcurrentLinkedQueue<AttemptContext>>()
    private val activeByCallKey = ConcurrentHashMap<Int, AttemptContext>()

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    fun markOutgoingDial(peerPhone: String, protocolEnabled: Boolean) {
        val now = System.currentTimeMillis()
        val attempt = AttemptContext(
            attemptId = UUID.randomUUID().toString(),
            direction = "outgoing",
            protocolEnabled = protocolEnabled,
            peerPhone = peerPhone,
            peerUri = "tel:$peerPhone",
            dialSentAtUnixMs = now
        )

        val key = normalizePhone(peerPhone)
        pendingOutgoingByPeer.getOrPut(key) { ConcurrentLinkedQueue() }.add(attempt)
    }

    fun onCallAdded(call: Call) {
        val context = appContext ?: return
        val callKey = System.identityHashCode(call)

        val direction = if (call.details.callDirection == Call.Details.DIRECTION_INCOMING) "incoming" else "outgoing"
        val peerUri = call.details.handle?.toString().orEmpty()
        val peerPhone = call.details.handle?.schemeSpecificPart.orEmpty()

        if (direction == "outgoing") {
            val pending = pendingOutgoingByPeer[normalizePhone(peerPhone)]?.poll()
            val attempt = pending ?: AttemptContext(
                attemptId = UUID.randomUUID().toString(),
                direction = "outgoing",
                protocolEnabled = (App.diaConfig != null && context.config.diaProtocolEnabled),
                peerPhone = peerPhone,
                peerUri = peerUri,
                dialSentAtUnixMs = 0L
            )

            attempt.callId = callKey.toString()
            activeByCallKey[callKey] = attempt
            return
        }

        // Incoming: create context for potential ODA measurements (no setup latency row).
        val attempt = AttemptContext(
            attemptId = UUID.randomUUID().toString(),
            direction = "incoming",
            protocolEnabled = (App.diaConfig != null && context.config.diaProtocolEnabled),
            peerPhone = peerPhone,
            peerUri = peerUri,
            dialSentAtUnixMs = 0L
        )
        attempt.callId = callKey.toString()
        activeByCallKey[callKey] = attempt
    }

    fun onCallAnswered(call: Call) {
        val callKey = System.identityHashCode(call)
        val attempt = activeByCallKey[callKey] ?: return
        if (attempt.direction != "outgoing") {
            return
        }
        if (attempt.answeredEmitted) {
            return
        }
        if (attempt.dialSentAtUnixMs <= 0L) {
            return
        }

        val answeredAt = System.currentTimeMillis()
        attempt.answeredAtUnixMs = answeredAt
        attempt.answeredEmitted = true

        val latency = answeredAt - attempt.dialSentAtUnixMs
        appendRecord(
            attempt = attempt,
            answeredAtUnixMs = answeredAt,
            latencyMs = latency,
            outcome = "answered",
            error = ""
        )
    }

    fun onCallRemoved(call: Call) {
        val callKey = System.identityHashCode(call)
        activeByCallKey.remove(callKey)
    }

    fun onOdaRequested(call: Call) {
        val callKey = System.identityHashCode(call)
        val attempt = activeByCallKey[callKey] ?: return
        attempt.odaRequestedAtUnixMs = System.currentTimeMillis()
    }

    fun onOdaCompleted(call: Call, outcome: String, error: String = "") {
        val callKey = System.identityHashCode(call)
        val attempt = activeByCallKey[callKey] ?: return
        val reqAt = attempt.odaRequestedAtUnixMs
        if (reqAt <= 0L) {
            return
        }

        val doneAt = System.currentTimeMillis()
        val odaLatency = doneAt - reqAt
        appendRecord(
            attempt = attempt,
            odaReqUnixMs = reqAt,
            odaDoneUnixMs = doneAt,
            odaLatencyMs = odaLatency,
            outcome = outcome,
            error = error,
        )

        attempt.odaRequestedAtUnixMs = 0L
    }

    private fun appendRecord(
        attempt: AttemptContext,
        answeredAtUnixMs: Long = 0L,
        latencyMs: Long = 0L,
        odaReqUnixMs: Long = 0L,
        odaDoneUnixMs: Long = 0L,
        odaLatencyMs: Long = 0L,
        outcome: String,
        error: String,
    ) {
        scope.launch {
            val context = appContext ?: return@launch
            val selfPhone = Storage.loadEnrolledPhone().orEmpty()

            val rec = listOf(
                attempt.attemptId,
                attempt.callId,
                selfPhone,
                attempt.peerPhone,
                attempt.peerUri,
                attempt.direction,
                attempt.protocolEnabled.toString(),
                attempt.dialSentAtUnixMs.toString(),
                answeredAtUnixMs.toString(),
                latencyMs.toString(),
                odaReqUnixMs.toString(),
                odaDoneUnixMs.toString(),
                odaLatencyMs.toString(),
                outcome,
                error
            )

            synchronized(fileLock) {
                try {
                    val file = resultsFile(context)
                    ensureHeader(file)
                    FileWriter(file, true).use { fw ->
                        fw.append(rec.joinToString(",") { escapeCsv(it) })
                        fw.append("\n")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "CSV write failed: ${e.message}", e)
                }
            }
        }
    }

    private fun resultsFile(context: Context): File {
        val dir = context.getExternalFilesDir(null) ?: context.filesDir
        return File(dir, FILE_NAME)
    }

    private fun ensureHeader(file: File) {
        if (file.exists() && file.length() > 0) {
            return
        }
        file.parentFile?.mkdirs()
        FileWriter(file, true).use { fw ->
            fw.append(header.joinToString(",") { escapeCsv(it) })
            fw.append("\n")
        }
    }

    private fun escapeCsv(value: String): String {
        val needsQuoting = value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r')
        if (!needsQuoting) {
            return value
        }
        return "\"${value.replace("\"", "\"\"")}\""
    }

    private fun normalizePhone(phone: String): String {
        return phone.filter { it.isDigit() }
    }
}
