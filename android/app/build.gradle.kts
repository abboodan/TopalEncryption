import java.util.Properties
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// The repository root: the Rust workspace that holds `core/` and `android/rust/`.
val workspaceDir: File = rootProject.projectDir.parentFile

// One version for the whole project: the one of the Rust workspace.
val workspaceVersion: String = Regex("(?m)^version\\s*=\\s*\"(\\d+\\.\\d+\\.\\d+)\"")
    .find(File(workspaceDir, "Cargo.toml").readText())
    ?.groupValues?.get(1)
    ?: throw GradleException("No version found in the workspace Cargo.toml")
val versionParts: List<Int> = workspaceVersion.split('.').map { it.toInt() }

// For testing the in-app update only: `-Ptopal.pretendVersionCode=209` builds an app that
// looks for updates as if it were that old, so the release already published counts as
// newer. The About screen says so. Never passed when building a release to publish.
val pretendVersionCode: Int = (findProperty("topal.pretendVersionCode") as String?)?.toInt() ?: 0

// Release signing is read from android/keystore.properties, which is not in the repository.
// Without it, release builds are left unsigned.
val keystoreFile: File = rootProject.file("keystore.properties")
val keystore: Properties? =
    if (keystoreFile.isFile) Properties().apply { keystoreFile.inputStream().use { load(it) } } else null

android {
    namespace = "io.github.abboodan.topalencryption"
    compileSdk {
        version = release(36) { minorApiLevel = 1 }
    }
    ndkVersion = "28.2.13676358"

    defaultConfig {
        applicationId = "io.github.abboodan.topalencryption"
        minSdk = 33
        targetSdk = 36
        versionCode = versionParts[0] * 10000 + versionParts[1] * 100 + versionParts[2]
        versionName = workspaceVersion
        buildConfigField("int", "PRETEND_VERSION_CODE", pretendVersionCode.toString())
        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        if (keystore != null) {
            create("release") {
                fun need(name: String): String =
                    keystore.getProperty(name)?.takeIf { it.isNotBlank() }
                        ?: throw GradleException("${keystoreFile.path} has no '$name' entry.")
                storeFile = File(need("storeFile"))
                storePassword = need("storePassword")
                keyAlias = need("keyAlias")
                keyPassword = need("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            // Not minified: the native library finds Kotlin classes and methods by name.
            isMinifyEnabled = false
            if (keystore != null) signingConfig = signingConfigs.getByName("release")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

/**
 * Builds `libtopal_android.so` for every ABI with cargo-ndk. Needs Rust with the Android
 * targets and `cargo install cargo-ndk`; see the README.
 */
abstract class CargoNdkBuild : DefaultTask() {
    @get:Inject
    abstract val exec: ExecOperations

    @get:Internal
    abstract val workspace: DirectoryProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sources: ConfigurableFileCollection

    @get:Input
    abstract val ndkPath: Property<String>

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val apiLevel: Property<Int>

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun build() {
        val windows = System.getProperty("os.name").startsWith("Windows")
        val home = File(System.getProperty("user.home"), ".cargo/bin/cargo" + if (windows) ".exe" else "")
        val cargo = System.getenv("CARGO") ?: if (home.isFile) home.path else "cargo"
        val out = outputDir.get().asFile
        out.deleteRecursively()
        val targets = abis.get().flatMap { listOf("-t", it) }
        exec.exec {
            workingDir = workspace.get().asFile
            environment("ANDROID_NDK_HOME", ndkPath.get())
            // RustCrypto's ChaCha20 uses NEON on ARM only when asked to; arm64 always has it.
            environment("CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS", "--cfg chacha20_force_neon")
            commandLine(
                listOf(cargo, "ndk") + targets +
                    listOf("-P", apiLevel.get().toString(), "-o", out.path, "build", "--release", "-p", "topal-android")
            )
        }
    }
}

val cargoNdkBuild = tasks.register<CargoNdkBuild>("cargoNdkBuild") {
    group = "build"
    description = "Builds the Rust library for Android"
    workspace.set(workspaceDir)
    sources.from(
        File(workspaceDir, "Cargo.toml"),
        File(workspaceDir, "Cargo.lock"),
        fileTree(File(workspaceDir, "core")) { include("Cargo.toml", "src/**") },
        fileTree(File(workspaceDir, "android/rust")) { include("Cargo.toml", "src/**") },
    )
    ndkPath.set(androidComponents.sdkComponents.ndkDirectory.map { it.asFile.absolutePath })
    abis.set(listOf("arm64-v8a", "x86_64"))
    apiLevel.set(33)
    outputDir.set(layout.buildDirectory.dir("rustJniLibs"))
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(cargoNdkBuild, CargoNdkBuild::outputDir)
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.foundation)
    implementation(libs.compose.material3)
    implementation(libs.activity.compose)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.coroutines.android)
}
