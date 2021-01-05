/*
 * Copyright 2021 Bloomberg Finance L.P.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

plugins {
    kotlin("jvm")
    jacoco
}

description = "Selekt core library."

disableKotlinCompilerAssertions()

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

dependencies {
    compileOnly(selekt("annotations", selektVersionName))
    implementation(selekt("api", selektVersionName))
    implementation(selekt("commons", selektVersionName))
    implementation(selekt("pools", selektVersionName))
    implementation(selekt("sqlite3", selektVersionName))
}

tasks.register("assembleSelekt") {
    dependsOn("assemble")
}
