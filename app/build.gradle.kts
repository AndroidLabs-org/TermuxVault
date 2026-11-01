plugins {
    id("com.android.application")
}

val vaultSigningStoreFile = providers.gradleProperty("vaultSigningStoreFile").orNull
val vaultSigningStorePassword = providers.gradleProperty("vaultSigningStorePassword").orNull
val vaultSigningKeyAlias = providers.gradleProperty("vaultSigningKeyAlias").orNull
val vaultSigningKeyPassword = providers.gradleProperty("vaultSigningKeyPassword").orNull

// Shown in Settings. Set with versionName/versionCode at each release; a fixed value (not the
// current time) keeps the build reproducible for F-Droid.
val releaseDate = "2026-10-26"

android {
    namespace = "app.termuxvault.secure"
    compileSdk {
        version = release(37) {
            minorApiLevel = 0
        }
    }

    defaultConfig {
        applicationId = "org.androidlabs.termuxvault"
        minSdk = 30
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0"
        resValue("string", "build_date", releaseDate)

        testInstrumentationRunner = "android.app.Instrumentation"
    }

    buildFeatures {
        buildConfig = false
        resValues = true
    }

    // AGP otherwise adds an encrypted "Dependency metadata" block to the APK signing block.
    // F-Droid's scanner rejects it, and it carries nothing the app needs.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    signingConfigs {
        if (vaultSigningStoreFile != null) {
            create("vaultRelease") {
                storeFile = file(vaultSigningStoreFile)
                storePassword = requireNotNull(vaultSigningStorePassword)
                keyAlias = requireNotNull(vaultSigningKeyAlias)
                keyPassword = requireNotNull(vaultSigningKeyPassword)
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
                enableV4Signing = true
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
        }
        release {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            // AGP would otherwise write the checked-out git commit into META-INF, which differs
            // between the private and public repos and between CI and F-Droid checkouts.
            vcsInfo {
                include = false
            }
            if (vaultSigningStoreFile != null) {
                signingConfig = signingConfigs.getByName("vaultRelease")
            }
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = true
        disable += setOf("OldTargetApi", "GradleDependency", "AndroidGradlePluginVersion")
    }

    packaging {
        resources.excludes += setOf(
            "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
            "META-INF/DEPENDENCIES"
        )
    }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.85")
    testImplementation("junit:junit:4.13.2")
}
