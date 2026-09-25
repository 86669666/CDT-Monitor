plugins {
    id("com.android.application")
}

android {
    namespace = "com.wang4386.cdtmonitor.widget"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.wang4386.cdtmonitor.widget"
        minSdk = 24
        targetSdk = 35
        versionCode = System.getenv("ANDROID_VERSION_CODE")?.toIntOrNull() ?: 2
        versionName = System.getenv("ANDROID_VERSION_NAME") ?: "1.0.1"
    }

    val releaseKeystore = System.getenv("ANDROID_KEYSTORE_FILE")
    signingConfigs {
        if (!releaseKeystore.isNullOrBlank()) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (!releaseKeystore.isNullOrBlank()) {
                signingConfig = signingConfigs.getByName("release")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    // Prototype CI ships one APK per build type plus an AAB. Do not
    // restore ABI splits without a packaging reason; they multiply
    // assemble time on the manual widget workflow.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
