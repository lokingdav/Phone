package org.fossify.phone.extensions

import android.annotation.SuppressLint
import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.ContactsContract
import android.telecom.PhoneAccount
import android.telecom.PhoneAccountHandle
import android.telecom.TelecomManager
import org.fossify.commons.activities.BaseSimpleActivity
import org.fossify.commons.dialogs.CallConfirmationDialog
import org.fossify.commons.extensions.*
import org.fossify.commons.helpers.*
import org.fossify.commons.models.contacts.Contact
import org.fossify.phone.activities.DialerActivity
import org.fossify.phone.activities.SimpleActivity
import org.fossify.phone.dialogs.SelectSIMDialog
import org.fossify.phone.callerauth.AuthService
import org.fossify.phone.helpers.CallManager
import org.fossify.phone.App
import android.util.Log

fun SimpleActivity.startCallIntent(recipient: String) {
    Log.d("CallAuth", "startCallIntent called for: $recipient")
    
    // If enrolled, start authentication protocol before placing call
    if (App.diaConfig != null) {
        Log.d("CallAuth", "User is enrolled, starting auth protocol")
        
        // Capture activity reference for callback
        val activity = this
        
        AuthService.startOutgoingCall(
            recipient = recipient,
            onReadyToCall = {
                Log.d("CallAuth", "onReadyToCall callback - placing call now")
                // Authentication initialized, now place the actual call
                activity.runOnUiThread {
                    try {
                        if (activity.isDefaultDialer()) {
                            activity.getHandleToUse(null, recipient) { handle ->
                                activity.launchCallIntent(recipient, handle)
                            }
                        } else {
                            activity.launchCallIntent(recipient, null)
                        }
                    } catch (e: Exception) {
                        Log.e("CallAuth", "Error placing call: ${e.message}", e)
                    }
                }
            },
            onProtocolComplete = { success, remoteParty ->
                if (success && remoteParty != null) {
                    Log.d("CallAuth", "Verified recipient: ${remoteParty.name} (${remoteParty.phone})")
                    // Notify CallManager so UI can show verified recipient
                    CallManager.onOutgoingCallVerified(remoteParty)
                } else {
                    Log.w("CallAuth", "Outgoing authentication failed or recipient not verified")
                    CallManager.onOutgoingCallAuthFailed()
                }
            }
        )
    } else {
        Log.d("CallAuth", "User not enrolled, placing call directly")
        // Not enrolled - place call directly without authentication
        if (isDefaultDialer()) {
            getHandleToUse(null, recipient) { handle ->
                launchCallIntent(recipient, handle)
            }
        } else {
            launchCallIntent(recipient, null)
        }
    }
}

fun SimpleActivity.startCallWithConfirmationCheck(recipient: String, name: String) {
    Log.d("CallAuth", "startCallWithConfirmationCheck called for: $recipient")
    if (config.showCallConfirmation) {
        CallConfirmationDialog(this, name) {
            startCallIntent(recipient)
        }
    } else {
        startCallIntent(recipient)
    }
}

fun SimpleActivity.launchCreateNewContactIntent() {
    Intent().apply {
        action = Intent.ACTION_INSERT
        data = ContactsContract.Contacts.CONTENT_URI
        launchActivityIntent(this)
    }
}

fun BaseSimpleActivity.callContactWithSim(recipient: String, useMainSIM: Boolean) {
    handlePermission(PERMISSION_READ_PHONE_STATE) {
        val wantedSimIndex = if (useMainSIM) 0 else 1
        val handle = getAvailableSIMCardLabels().sortedBy { it.id }.getOrNull(wantedSimIndex)?.handle
        launchCallIntent(recipient, handle)
    }
}

fun BaseSimpleActivity.callContactWithSimWithConfirmationCheck(recipient: String, name: String, useMainSIM: Boolean) {
    if (config.showCallConfirmation) {
        CallConfirmationDialog(this, name) {
            callContactWithSim(recipient, useMainSIM)
        }
    } else {
        callContactWithSim(recipient, useMainSIM)
    }
}

// handle private contacts differently, only Simple Contacts Pro can open them
fun Activity.startContactDetailsIntent(contact: Contact) {
    val simpleContacts = "org.fossify.contacts"
    val simpleContactsDebug = "org.fossify.contacts.debug"
    if (contact.rawId > 1000000 && contact.contactId > 1000000 && contact.rawId == contact.contactId &&
        (isPackageInstalled(simpleContacts) || isPackageInstalled(simpleContactsDebug))
    ) {
        Intent().apply {
            action = Intent.ACTION_VIEW
            putExtra(CONTACT_ID, contact.rawId)
            putExtra(IS_PRIVATE, true)
            `package` = if (isPackageInstalled(simpleContacts)) simpleContacts else simpleContactsDebug
            setDataAndType(ContactsContract.Contacts.CONTENT_LOOKUP_URI, "vnd.android.cursor.dir/person")
            launchActivityIntent(this)
        }
    } else {
        ensureBackgroundThread {
            val lookupKey = SimpleContactsHelper(this).getContactLookupKey((contact).rawId.toString())
            val publicUri = Uri.withAppendedPath(ContactsContract.Contacts.CONTENT_LOOKUP_URI, lookupKey)
            runOnUiThread {
                launchViewContactIntent(publicUri)
            }
        }
    }
}

// used at devices with multiple SIM cards
@SuppressLint("MissingPermission")
fun SimpleActivity.getHandleToUse(intent: Intent?, phoneNumber: String, callback: (handle: PhoneAccountHandle?) -> Unit) {
    handlePermission(PERMISSION_READ_PHONE_STATE) {
        if (it) {
            val defaultHandle = telecomManager.getDefaultOutgoingPhoneAccount(PhoneAccount.SCHEME_TEL)
            when {
                intent?.hasExtra(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE) == true -> callback(intent.getParcelableExtra(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE)!!)
                config.getCustomSIM(phoneNumber) != null -> {
                    callback(config.getCustomSIM(phoneNumber))
                }

                defaultHandle != null -> callback(defaultHandle)
                else -> {
                    SelectSIMDialog(this, phoneNumber, onDismiss = {
                        if (this is DialerActivity) {
                            finish()
                        }
                    }) { handle ->
                        callback(handle)
                    }
                }
            }
        }
    }
}
