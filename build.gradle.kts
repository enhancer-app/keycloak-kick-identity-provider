plugins {
    `java-library`
    `maven-publish`
}

group = "io.github.enhancer-app"
version = providers.gradleProperty("version").getOrElse("1.0.0-SNAPSHOT")
description = "Kick (kick.com) social identity provider for Keycloak"

val keycloakVersion = libs.versions.keycloak.get()

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
    withSourcesJar()
    withJavadocJar()
}

dependencies {
    // Everything Keycloak already ships inside the distribution is compile-only.
    // The produced JAR must not bundle Keycloak, Jackson, HTTP or logging libraries.
    compileOnly(libs.keycloak.core)
    compileOnly(libs.keycloak.common)
    compileOnly(libs.keycloak.server.spi)
    compileOnly(libs.keycloak.server.spi.private)
    compileOnly(libs.keycloak.services)
    compileOnly(libs.jakarta.ws.rs)
    compileOnly(libs.jackson.databind)
    compileOnly(libs.jboss.logging)
    compileOnly(libs.httpclient)

    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.assertj)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.junit.jupiter)

    // The same libraries, on the test runtime classpath, to emulate the Keycloak runtime.
    testImplementation(libs.keycloak.core)
    testImplementation(libs.keycloak.common)
    testImplementation(libs.keycloak.server.spi)
    testImplementation(libs.keycloak.server.spi.private)
    testImplementation(libs.keycloak.services)
    testImplementation(libs.jakarta.ws.rs)
    testImplementation(libs.jackson.databind)
    testImplementation(libs.jboss.logging)
    testImplementation(libs.httpclient)

    // Keycloak's broker code builds URIs through jakarta.ws.rs UriBuilder, which resolves a
    // RuntimeDelegate via ServiceLoader. The API jar alone has no implementation, so the tests
    // need the same RESTEasy the Keycloak distribution runs on.
    testImplementation(libs.resteasy.core)

    // Container smoke test only. The JUnit 5 lifecycle is driven by hand rather than via the
    // @Testcontainers extension, so no extra Testcontainers module is needed.
    testImplementation(libs.testcontainers)
    testRuntimeOnly(libs.slf4j.simple)
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-processing"))
}

tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).apply {
        encoding = "UTF-8"
        addStringOption("Xdoclint:none", "-quiet")
    }
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to "keycloak-kick-identity-provider",
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "keycloak-kick-identity-provider contributors",
            "Keycloak-Target-Version" to keycloakVersion,
        )
    }
}

/**
 * The container smoke test boots a real Keycloak image and is therefore opt-in.
 * Enable with: ./gradlew test -PwithSmoke
 */
val withSmoke = providers.gradleProperty("withSmoke").isPresent

tasks.test {
    useJUnitPlatform {
        if (!withSmoke) {
            excludeTags("smoke")
        }
    }
    systemProperty("kick.keycloakVersion", keycloakVersion)
    systemProperty("kick.providerJar", tasks.jar.flatMap { it.archiveFile }.get().asFile.absolutePath)
    // Makes JBoss Logging delegate to java.util.logging in tests, allowing KickLogRedactionTest
    // to inspect the exact emitted log records without adding a runtime logging dependency.
    systemProperty("org.jboss.logging.provider", "jdk")
    testLogging {
        events("passed", "skipped", "failed")
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

if (withSmoke) {
    tasks.test { dependsOn(tasks.jar) }
}

publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            artifactId = "keycloak-kick-identity-provider"
            pom {
                name.set("Keycloak Kick Identity Provider")
                description.set(project.description)
                url.set("https://github.com/enhancer-app/keycloak-kick-identity-provider")
                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }
                scm {
                    url.set("https://github.com/enhancer-app/keycloak-kick-identity-provider")
                    connection.set("scm:git:https://github.com/enhancer-app/keycloak-kick-identity-provider.git")
                }
            }
        }
    }
}
