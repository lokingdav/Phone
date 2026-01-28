package org.fossify.phone.services

import android.app.KeyguardManager
import android.content.Context
import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.InCallService
import android.telecom.VideoProfile
import org.fossify.phone.activities.CallActivity
import org.fossify.phone.extensions.config
import org.fossify.phone.extensions.isOutgoing
import org.fossify.phone.extensions.powerManager
import org.fossify.phone.helpers.CallManager
import org.fossify.phone.helpers.CallManagerListener
import org.fossify.phone.helpers.CallNotificationManager
import org.fossify.phone.helpers.NoCall
import org.fossify.phone.models.AudioRoute
import org.fossify.phone.models.Events
import org.greenrobot.eventbus.EventBus

class CallService : InCallService() {
    private val callNotificationManager by lazy { CallNotificationManager(this) }

    private fun shouldAutoAnswer(call: Call): Boolean {
        return call.details.callDirection == Call.Details.DIRECTION_INCOMING && config.autoAnswer
    }

    private fun autoAnswer(call: Call) {
        if (call.state != Call.STATE_RINGING) return
        call.answer(VideoProfile.STATE_AUDIO_ONLY)
    }

    private val callListener = object : Call.Callback() {
        override fun onStateChanged(call: Call, state: Int) {
            super.onStateChanged(call, state)
            if (state == Call.STATE_DISCONNECTED || state == Call.STATE_DISCONNECTING) {
                callNotificationManager.cancelNotification()
            } else {
                callNotificationManager.setupNotification()
            }
        }
    }
    
    private val callManagerListener = object : CallManagerListener {
        override fun onStateChanged() {}
        override fun onAudioStateChanged(audioState: AudioRoute) {}
        override fun onPrimaryCallChanged(call: Call) {}
        
        override fun onCallAuthCompleted(call: Call, success: Boolean) {
            android.util.Log.d("CallService", "Auth completed for call")
            // Keep behavior: auto-answer happens only after DIA auth completes.
            if (shouldAutoAnswer(call)) {
                autoAnswer(call)
            }
        }
    }

    override fun onCallAdded(call: Call) {
        super.onCallAdded(call)
        CallManager.inCallService = this
        CallManager.onCallAdded(call)
        CallManager.addListener(callManagerListener)
        call.registerCallback(callListener)

        if (shouldAutoAnswer(call)) {
            autoAnswer(call)
            return
        }

        showCallUI(call)
    }
    
    private fun showCallUI(call: Call) {
        val isScreenLocked = (getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager).isDeviceLocked
        if (!powerManager.isInteractive || call.isOutgoing() || isScreenLocked || config.alwaysShowFullscreen) {
            try {
                callNotificationManager.setupNotification(true)
                startActivity(CallActivity.getStartIntent(this))
            } catch (e: Exception) {
                // seems like startActivity can throw AndroidRuntimeException and ActivityNotFoundException, not yet sure when and why, lets show a notification
                callNotificationManager.setupNotification()
            }
        } else {
            callNotificationManager.setupNotification()
        }
    }

    override fun onCallRemoved(call: Call) {
        super.onCallRemoved(call)
        call.unregisterCallback(callListener)
        val wasPrimaryCall = call == CallManager.getPrimaryCall()
        CallManager.onCallRemoved(call)
        if (CallManager.getPhoneState() == NoCall) {
            CallManager.inCallService = null
            CallManager.removeListener(callManagerListener)
            callNotificationManager.cancelNotification()
        } else {
            callNotificationManager.setupNotification()
            if (wasPrimaryCall) {
                startActivity(CallActivity.getStartIntent(this))
            }
        }

        EventBus.getDefault().post(Events.RefreshCallLog)
    }

    override fun onCallAudioStateChanged(audioState: CallAudioState?) {
        super.onCallAudioStateChanged(audioState)
        if (audioState != null) {
            CallManager.onAudioStateChanged(audioState)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        CallManager.removeListener(callManagerListener)
        callNotificationManager.cancelNotification()
    }
}
