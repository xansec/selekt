/*
 * Copyright 2022 Bloomberg Finance L.P.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    id("com.android.library")
    id("kotlin-android")
    id("androidx.benchmark") version Versions.ANDROID_BENCHMARK.version
}

repositories {
    mavenCentral()
    google()
}

android {
    compileSdkVersion(Versions.ANDROID_SDK.version.toInt())
    buildToolsVersion(Versions.ANDROID_BUILD_TOOLS.version)
    namespace = "com.bloomberg.selekt.android.benchmark"
    defaultConfig {
        minSdkVersion(21)
        targetSdkVersion(32)
        testInstrumentationRunner = "androidx.benchmark.junit4.AndroidBenchmarkRunner"
        testInstrumentationRunnerArguments.putAll(arrayOf(
            "androidx.benchmark.suppressErrors" to "EMULATOR,LOW_BATTERY,UNLOCKED"
        ))
    }
    arrayOf("androidTest").forEach {
        sourceSets[it].java.srcDir("src/$it/kotlin")
    }
    lintOptions {
        disable("OldTargetApi")
    }
}

dependencies {
    androidTestImplementation(projects.selektAndroid)
    androidTestImplementation("junit:junit:${Versions.JUNIT4}")
    androidTestImplementation("androidx.test:runner:1.5.2")
    androidTestImplementation("androidx.test:rules:1.5.0")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation(androidX("benchmark", "junit4", Versions.ANDROID_BENCHMARK.version))
    androidTestImplementation(kotlin("test", Versions.KOTLIN.version))
    androidTestImplementation(kotlin("test-junit", Versions.KOTLIN.version))
    androidTestImplementation(kotlinX("coroutines-core", Versions.KOTLINX_COROUTINES.version))
    testImplementation(kotlinX("coroutines-core", Versions.KOTLINX_COROUTINES.version))
}
