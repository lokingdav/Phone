package org.fossify.phone

import org.fossify.commons.FossifyApp
import org.fossify.phone.callerauth.Storage

class App : FossifyApp() {
    override fun onCreate() {
        super.onCreate()

        Storage.init(this)
        // TODO: Initialize LibDia v2 config from storage
    }
}
