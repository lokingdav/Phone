package org.fossify.phone

import android.util.Log
import org.fossify.commons.FossifyApp
import org.fossify.phone.denseid.DenseIdentityService
import org.fossify.phone.denseid.Storage
import org.fossify.phone.denseid.Signing
import org.fossify.phone.denseid.UserState

class App : FossifyApp() {
    override fun onCreate() {
        super.onCreate()

        Signing.initGroupSignatures()
        Storage.init(this)
        UserState.load()
    }
}
