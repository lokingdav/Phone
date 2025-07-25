import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jetbrains.kotlin.konan.properties.Properties
import java.io.FileInputStream
import com.google.protobuf.gradle.*

plugins {
    alias(libs.plugins.android)
    alias(libs.plugins.kotlinAndroid)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.detekt)
    id("com.google.protobuf") version "0.9.5"
}

data class Server(val host: String, val port: String)
val defaultHost = "10.0.2.2"
val SERVERS: Map<String, Server> = mapOf(
    // Enrollment Servers
    "es1" to Server(
        host = System.getenv("ES1_HOST") ?: defaultHost,
        port = System.getenv("ES1_PORT") ?: "50051"
    ),
    "es2" to Server(
        host = System.getenv("ES2_HOST") ?: defaultHost,
        port = System.getenv("ES2_PORT") ?: "50052"
    ),
    // Key Derivation Servers
    "kd1" to Server(
        host = System.getenv("KD1_HOST") ?: defaultHost,
        port = System.getenv("KD1_PORT") ?: "50053"
    ),
    "kd2" to Server(
        host = System.getenv("KD2_HOST") ?: defaultHost,
        port = System.getenv("KD2_PORT") ?: "50054"
    ),
    // Revocation Servers
    "rvk" to Server(
        host = System.getenv("RVK_HOST") ?: defaultHost,
        port = System.getenv("RVK_PORT") ?: "50055"
    ),
    // Relay Server
    "rel" to Server(
        host = System.getenv("RS_HOST") ?: defaultHost,
        port = System.getenv("RS_PORT") ?: "50054"
    )
)

val keystorePropertiesFile: File = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

fun hasSigningVars(): Boolean {
    return providers.environmentVariable("SIGNING_KEY_ALIAS").orNull != null
        && providers.environmentVariable("SIGNING_KEY_PASSWORD").orNull != null
        && providers.environmentVariable("SIGNING_STORE_FILE").orNull != null
        && providers.environmentVariable("SIGNING_STORE_PASSWORD").orNull != null
}

android {
    compileSdk = project.libs.versions.app.build.compileSDKVersion.get().toInt()

    defaultConfig {
        applicationId = project.property("APP_ID").toString()
        minSdk = project.libs.versions.app.build.minimumSDK.get().toInt()
        targetSdk = project.libs.versions.app.build.targetSDK.get().toInt()
        versionName = project.property("VERSION_NAME").toString()
        versionCode = project.property("VERSION_CODE").toString().toInt()
        setProperty("archivesBaseName", "phone-$versionCode")

        // Enrollment Servers
        val es1 = SERVERS["es1"]
        buildConfigField("String", "ES1_HOST", "\"${es1?.host}\"")
        buildConfigField("int",    "ES1_PORT", es1?.port!!)
        val es2 = SERVERS["es2"]
        buildConfigField("String", "ES2_HOST", "\"${es2?.host}\"")
        buildConfigField("int",    "ES2_PORT", es2?.port!!)

        // Key Derivation Servers
        val kd1 = SERVERS["kd1"]
        buildConfigField("String", "KD1_HOST", "\"${kd1?.host}\"")
        buildConfigField("int",    "KD1_PORT", kd1?.port!!)
        val kd2 = SERVERS["kd2"]
        buildConfigField("String", "KD2_HOST", "\"${kd2?.host}\"")
        buildConfigField("int",    "KD2_PORT", kd2?.port!!)

        // Revocation Servers
        val rvk = SERVERS["rvk"]
        buildConfigField("String", "RVK_HOST", "\"${rvk?.host}\"")
        buildConfigField("int",    "RVK_PORT", rvk?.port!!)

        // Relay Server
        val rs = SERVERS["rel"]
        buildConfigField("String", "RS_HOST", "\"${rs?.host}\"")
        buildConfigField("int",    "RS_PORT", rs?.port!!)
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            register("release") {
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
                storeFile = file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
            }
        } else if (hasSigningVars()) {
            register("release") {
                keyAlias = providers.environmentVariable("SIGNING_KEY_ALIAS").get()
                keyPassword = providers.environmentVariable("SIGNING_KEY_PASSWORD").get()
                storeFile = file(providers.environmentVariable("SIGNING_STORE_FILE").get())
                storePassword = providers.environmentVariable("SIGNING_STORE_PASSWORD").get()
            }
        } else {
            logger.warn("Warning: No signing config found. Build will be unsigned.")
        }
    }

    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            if (keystorePropertiesFile.exists() || hasSigningVars()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    flavorDimensions.add("variants")
    productFlavors {
        register("core")
        register("foss")
        register("gplay")
    }

    sourceSets {
        getByName("main").java.srcDirs("src/main/kotlin")
        // Add the generated proto sources to the source set
        getByName("main").java.srcDirs("build/generated/sources/proto/main/java")
        getByName("main").java.srcDirs("build/generated/sources/proto/main/grpc")
        getByName("main").java.srcDirs("build/generated/sources/proto/main/grpckt")
    }

    compileOptions {
        val currentJavaVersionFromLibs =
            JavaVersion.valueOf(libs.versions.app.build.javaVersion.get())
        sourceCompatibility = currentJavaVersionFromLibs
        targetCompatibility = currentJavaVersionFromLibs
    }

    dependenciesInfo {
        includeInApk = false
    }

    androidResources {
        @Suppress("UnstableApiUsage")
        generateLocaleConfig = true
    }

    tasks.withType<KotlinCompile> {
        compilerOptions.jvmTarget.set(
            JvmTarget.fromTarget(project.libs.versions.app.build.kotlinJVMTarget.get())
        )
    }

    namespace = project.property("APP_ID").toString()

    lint {
        checkReleaseBuilds = false
        abortOnError = true
        warningsAsErrors = false
        baseline = file("lint-baseline.xml")
        lintConfig = rootProject.file("lint.xml")
    }

    bundle {
        language {
            enableSplit = false
        }
    }

    packaging {
        resources.excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
    }
}

detekt {
    baseline = file("detekt-baseline.xml")
    config.setFrom("$rootDir/detekt.yml")
    buildUponDefaultConfig = true
    allRules = false
}

dependencies {
    implementation(libs.fossify.commons)
    implementation(libs.indicator.fast.scroll)
    implementation(libs.autofit.text.view)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.eventbus)
    implementation(libs.libphonenumber)
    implementation(libs.geocoder)
    detektPlugins(libs.compose.detekt)

    // Kotlin standard library
    implementation(kotlin("stdlib-jdk8"))

    // Coroutines (for gRPC Kotlin stubs)
    // Note: It's good practice to use a BOM (Bill of Materials) to manage coroutine versions
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")

    // gRPC Dependencies
    implementation(libs.grpc.okhttp)
    implementation(libs.grpc.protobuf.lite)
    implementation(libs.grpc.stub)
    implementation(libs.javax.annotation.api)

    // Added: Protobuf-javalite for core protobuf classes and well-known types like Timestamp
    implementation("com.google.protobuf:protobuf-javalite:3.25.3")

    // gRPC Kotlin stub runtime
    implementation("io.grpc:grpc-kotlin-stub:1.4.3")

    implementation("org.bouncycastle:bcprov-jdk18on:1.81")

    implementation(files("libs/bbsgslib-release.aar"))

    implementation("org.signal:libsignal-client:0.76.4")
}

// Protobuf configuration block
protobuf {
    protoc {
        // The version of the protobuf compiler
        artifact = "com.google.protobuf:protoc:3.25.3"
    }
    plugins {
        // Plugin for generating Java gRPC service stubs
        create("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:1.64.0"
        }
        // Plugin for generating Kotlin gRPC service stubs
        create("grpckt") {
            // FIX: Matched version with the grpc-kotlin-stub dependency (1.4.3)
            artifact = "io.grpc:protoc-gen-grpc-kotlin:1.4.3:jdk8@jar"
        }
    }
    generateProtoTasks {
        all().forEach { task ->
            // FIX: Configure the built-in 'java' plugin to generate message classes
            task.builtins {
                create("java") {
                    // Must generate 'lite' messages to match the 'grpc-protobuf-lite' runtime
                    option("lite")
                }
            }
            // Configure the external gRPC plugins
            task.plugins {
                id("grpc") {
                    // The generated service stubs must also be 'lite'
                    option("lite")
                }
                id("grpckt")
            }
        }
    }
}
