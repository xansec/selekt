/*
 * This file was generated by the Gradle 'init' task.
 *
 * This is a general purpose Gradle build.
 * Learn more about Gradle by exploring our samples at https://docs.gradle.org/8.0.2/samples
 * This project uses @Incubating APIs which are subject to change.
 */

 plugins {
     id("com.github.johnrengelman.shadow") version "8.1.1"
     id("java")
 }

 repositories {
     mavenCentral()
 }

 dependencies {
     implementation(files("/selekt/selekt-java/build/libs/selekt-java-0.20.0-SNAPSHOT.jar"))
     implementation("com.code-intelligence:jazzer-api:0.16.1")
     implementation("org.mockito:mockito-core:3.+")
 }
