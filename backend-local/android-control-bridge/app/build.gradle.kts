plugins {
    id("com.android.application")
}

android {
    namespace = "local.hdcamerapro.bridge"
    compileSdk = 36

    defaultConfig {
        applicationId = "local.hdcamerapro.bridge"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-beta"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
