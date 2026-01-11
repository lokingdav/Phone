package org.fossify.phone.helpers

import android.annotation.SuppressLint
import android.os.Handler
import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.InCallService
import android.telecom.VideoProfile
import org.fossify.phone.callerauth.AuthService
import org.fossify.phone.App
import org.fossify.phone.extensions.getStateCompat
import org.fossify.phone.extensions.hasCapability
import org.fossify.phone.extensions.isConference
import org.fossify.phone.extensions.config
import org.fossify.phone.metrics.MetricsRecorder
import org.fossify.phone.models.AudioRoute
import java.util.concurrent.CopyOnWriteArraySet

// inspired by https://github.com/Chooloo/call_manage
class CallManager {
    companion object {
        @SuppressLint("StaticFieldLeak")
        var inCallService: InCallService? = null
        private var call: Call? = null
        private val calls = mutableListOf<Call>()
        private val listeners = CopyOnWriteArraySet<CallManagerListener>()
        
        // Track calls pending authentication - UI should not be shown until auth completes
        private val callsPendingAuth = mutableSetOf<Call>()
        
        // Store verified remote party for late-joining listeners (e.g., CallActivity)
        private var verifiedRemoteParty: io.github.lokingdav.libdia.RemoteParty? = null
        
        fun getVerifiedRemoteParty(): io.github.lokingdav.libdia.RemoteParty? = verifiedRemoteParty
        
        fun isCallPendingAuth(call: Call?): Boolean {
            return call != null && callsPendingAuth.contains(call)
        }
        
        fun onCallAuthCompleted(call: Call, success: Boolean) {
            callsPendingAuth.remove(call)
            android.util.Log.d("CallManager", "Call auth completed: success=$success, notifying listeners")
            // Notify listeners that auth is complete so UI can be shown
            for (listener in listeners) {
                listener.onCallAuthCompleted(call, success)
            }
        }
        
        /**
         * Called when outgoing call authentication completes successfully.
         * Notifies listeners with the verified recipient identity.
         */
        fun onOutgoingCallVerified(remoteParty: io.github.lokingdav.libdia.RemoteParty) {
            android.util.Log.d("CallAuth", "Verified outgoing recipient: ${remoteParty.name} (${remoteParty.phone})")
            verifiedRemoteParty = remoteParty
            for (listener in listeners) {
                listener.onCallerVerified(remoteParty)
            }
        }
        
        /**
         * Called when outgoing call authentication fails.
         */
        fun onOutgoingCallAuthFailed() {
            android.util.Log.w("CallAuth", "Outgoing call authentication failed")
            verifiedRemoteParty = null
        }

        fun onCallAdded(call: Call) {
            MetricsRecorder.onCallAdded(call)

            if (call.details.callDirection == Call.Details.DIRECTION_INCOMING) {
                // Start authentication protocol for incoming calls if enrolled
                val protocolEnabledForAttempt = App.diaConfig != null && (inCallService?.applicationContext?.config?.diaProtocolEnabled == true)
                if (protocolEnabledForAttempt) {
                    // Mark call as pending auth - UI should not ring until auth completes
                    callsPendingAuth.add(call)
                    
                    AuthService.handleIncomingCall(call) { success, remoteParty ->
                        // Notify that auth is complete so UI can be shown
                        onCallAuthCompleted(call, success)
                        
                        if (success && remoteParty != null) {
                            android.util.Log.d("CallAuth", "Verified incoming caller: ${remoteParty.name} (${remoteParty.phone})")
                            // Store for late-joining listeners (e.g., CallActivity started after auth)
                            verifiedRemoteParty = remoteParty
                            // Notify listeners about verified caller identity
                            for (listener in listeners) {
                                listener.onCallerVerified(remoteParty)
                            }
                        } else {
                            android.util.Log.w("CallAuth", "Incoming call authentication failed or caller not verified")
                            verifiedRemoteParty = null
                        }
                    }
                }
            }

            this.call = call
            calls.add(call)
            for (listener in listeners) {
                listener.onPrimaryCallChanged(call)
            }
            call.registerCallback(object : Call.Callback() {
                override fun onStateChanged(call: Call, state: Int) {
                    if (state == Call.STATE_ACTIVE) {
                        MetricsRecorder.onCallAnswered(call)
                    }
                    updateState()
                }

                override fun onDetailsChanged(call: Call, details: Call.Details) {
                    updateState()
                }

                override fun onConferenceableCallsChanged(call: Call, conferenceableCalls: MutableList<Call>) {
                    updateState()
                }
            })
        }

        fun onCallRemoved(call: Call) {
            calls.remove(call)
            callsPendingAuth.remove(call)
            verifiedRemoteParty = null  // Clear verified party when call ends
            MetricsRecorder.onCallRemoved(call)
            updateState()
            
            // Clean up authentication when call ends
            AuthService.endCallCleanup()
        }

        fun onAudioStateChanged(audioState: CallAudioState) {
            val route = AudioRoute.fromRoute(audioState.route) ?: return
            for (listener in listeners) {
                listener.onAudioStateChanged(route)
            }
        }

        fun getPhoneState(): PhoneState {
            return when (calls.size) {
                0 -> NoCall
                1 -> SingleCall(calls.first())
                2 -> {
                    val active = calls.find { it.getStateCompat() == Call.STATE_ACTIVE }
                    val newCall = calls.find { it.getStateCompat() == Call.STATE_CONNECTING || it.getStateCompat() == Call.STATE_DIALING }
                    val onHold = calls.find { it.getStateCompat() == Call.STATE_HOLDING }
                    if (active != null && newCall != null) {
                        TwoCalls(newCall, active)
                    } else if (newCall != null && onHold != null) {
                        TwoCalls(newCall, onHold)
                    } else if (active != null && onHold != null) {
                        TwoCalls(active, onHold)
                    } else {
                        TwoCalls(calls[0], calls[1])
                    }
                }

                else -> {
                    val conference = calls.find { it.isConference() } ?: return NoCall
                    val secondCall = if (conference.children.size + 1 != calls.size) {
                        calls.filter { !it.isConference() }
                            .subtract(conference.children.toSet())
                            .firstOrNull()
                    } else {
                        null
                    }
                    if (secondCall == null) {
                        SingleCall(conference)
                    } else {
                        val newCallState = secondCall.getStateCompat()
                        if (newCallState == Call.STATE_ACTIVE || newCallState == Call.STATE_CONNECTING || newCallState == Call.STATE_DIALING) {
                            TwoCalls(secondCall, conference)
                        } else {
                            TwoCalls(conference, secondCall)
                        }
                    }
                }
            }
        }

        private fun getCallAudioState() = inCallService?.callAudioState

        fun getSupportedAudioRoutes(): Array<AudioRoute> {
            return AudioRoute.values().filter {
                val supportedRouteMask = getCallAudioState()?.supportedRouteMask
                if (supportedRouteMask != null) {
                    supportedRouteMask and it.route == it.route
                } else {
                    false
                }
            }.toTypedArray()
        }

        fun getCallAudioRoute() = AudioRoute.fromRoute(getCallAudioState()?.route)

        fun setAudioRoute(newRoute: Int) {
            inCallService?.setAudioRoute(newRoute)
        }

        private fun updateState() {
            val primaryCall = when (val phoneState = getPhoneState()) {
                is NoCall -> null
                is SingleCall -> phoneState.call
                is TwoCalls -> phoneState.active
            }
            var notify = true
            if (primaryCall == null) {
                call = null
            } else if (primaryCall != call) {
                call = primaryCall
                for (listener in listeners) {
                    listener.onPrimaryCallChanged(primaryCall)
                }
                notify = false
            }
            if (notify) {
                for (listener in listeners) {
                    listener.onStateChanged()
                }
            }

            // remove all disconnected calls manually in case they are still here
            calls.removeAll { it.getStateCompat() == Call.STATE_DISCONNECTED }
        }

        fun getPrimaryCall(): Call? {
            return call
        }

        fun getConferenceCalls(): List<Call> {
            return calls.find { it.isConference() }?.children ?: emptyList()
        }

        fun accept() {
            call?.answer(VideoProfile.STATE_AUDIO_ONLY)
        }

        fun reject() {
            if (call != null) {
                val state = getState()
                if (state == Call.STATE_RINGING) {
                    call!!.reject(false, null)
                } else if (state != Call.STATE_DISCONNECTED && state != Call.STATE_DISCONNECTING) {
                    call!!.disconnect()
                }
            }
        }

        fun toggleHold(): Boolean {
            val isOnHold = getState() == Call.STATE_HOLDING
            if (isOnHold) {
                call?.unhold()
            } else {
                call?.hold()
            }
            return !isOnHold
        }

        fun swap() {
            if (calls.size > 1) {
                calls.find { it.getStateCompat() == Call.STATE_HOLDING }?.unhold()
            }
        }

        fun merge() {
            val conferenceableCalls = call!!.conferenceableCalls
            if (conferenceableCalls.isNotEmpty()) {
                call!!.conference(conferenceableCalls.first())
            } else {
                if (call!!.hasCapability(Call.Details.CAPABILITY_MERGE_CONFERENCE)) {
                    call!!.mergeConference()
                }
            }
        }

        fun addListener(listener: CallManagerListener) {
            listeners.add(listener)
        }

        fun removeListener(listener: CallManagerListener) {
            listeners.remove(listener)
        }

        fun getState() = getPrimaryCall()?.getStateCompat()

        fun keypad(char: Char) {
            call?.playDtmfTone(char)
            Handler().postDelayed({
                call?.stopDtmfTone()
            }, DIALPAD_TONE_LENGTH_MS)
        }
    }
}

interface CallManagerListener {
    fun onStateChanged()
    fun onAudioStateChanged(audioState: AudioRoute)
    fun onPrimaryCallChanged(call: Call)
    fun onCallerVerified(remoteParty: io.github.lokingdav.libdia.RemoteParty) {}
    fun onCallAuthCompleted(call: Call, success: Boolean) {}
}

sealed class PhoneState
object NoCall : PhoneState()
class SingleCall(val call: Call) : PhoneState()
class TwoCalls(val active: Call, val onHold: Call) : PhoneState()
