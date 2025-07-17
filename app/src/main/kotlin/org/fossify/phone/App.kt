package org.fossify.phone

import org.fossify.commons.FossifyApp
import org.fossify.phone.denseid.Storage
import org.fossify.phone.denseid.Signing
import org.fossify.phone.denseid.UserState

class App : FossifyApp() {
    var denseIdState: UserState? = null

    override fun onCreate() {
        super.onCreate()

        Signing.initGroupSignatures()
        Storage.init(this)
        denseIdState = UserState.load()
    }
}
