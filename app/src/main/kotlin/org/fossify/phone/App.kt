package org.fossify.phone

import org.fossify.commons.FossifyApp
import org.fossify.phone.callerauth.Storage
import org.fossify.phone.callerauth.UserState

class App : FossifyApp() {
    override fun onCreate() {
        super.onCreate()

        Storage.init(this)
        UserState.load()
    }
}
