import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("net.saliman.properties") version "1.5.2"
    kotlin("jvm") version "1.8.21"
    `java-library`
    `maven-publish`
}

group = "pm.lily"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk15on:1.70")
    testImplementation(kotlin("test"))
}

publishing {
    publications {
        create<MavenPublication>("argon-dsl") {
            from(components["java"])
        }
    }

    repositories {
        maven {
            name = "rosaline-cloud-maven"
            url = uri("https://git.rosaline.cloud/api/packages/opus/maven")

            credentials(HttpHeaderCredentials::class.java) {
                name = "Authorization"
                value = "token " + (System.getenv("MAVEN_TOKEN") ?: project.property("maven_token") as String?)
            }

            authentication {
                create<HttpHeaderAuthentication>("header")
            }
        }
    }
}

tasks.test {
    useJUnitPlatform()
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}
