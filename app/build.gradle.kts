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
    // Enrollment Server
    "es" to Server(
        host = System.getenv("ES_HOST") ?: defaultHost,
        port = System.getenv("ES_PORT") ?: "50051"
    ),

    // Relay Server
    "rs" to Server(
        host = System.getenv("RS_HOST") ?: defaultHost,
        port = System.getenv("RS_PORT") ?: "50052"
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
        buildConfigField("String", "ES_HOST", "\"${SERVERS["es"]?.host}\"")
        buildConfigField("int",    "ES_PORT", SERVERS["es"]?.port!!)

        // Relay Server
        buildConfigField("String", "RS_HOST", "\"${SERVERS["rs"]?.host}\"")
        buildConfigField("int",    "RS_PORT", SERVERS["rs"]?.port!!)
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
