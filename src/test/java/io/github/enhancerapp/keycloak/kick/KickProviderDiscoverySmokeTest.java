/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.PullPolicy;
import org.testcontainers.utility.MountableFile;

/**
 * Boots the exact supported Keycloak image and proves it discovers the built provider JAR.
 *
 * <p>Excluded from the ordinary test task. Run explicitly with {@code ./gradlew test
 * -PwithSmoke}; Docker must be available. It mounts the just-built JAR into Keycloak's provider
 * directory and starts {@code start-dev}, which exercises Keycloak's build-time provider scan.
 */
@Tag("smoke")
class KickProviderDiscoverySmokeTest {

    private static final String KEYCLOAK_VERSION = System.getProperty("kick.keycloakVersion", "26.5.2");
    private static final Path PROVIDER_JAR = Path.of(System.getProperty("kick.providerJar"));

    @Test
    void keycloakDiscoversKickAsASocialProvider() throws Exception {
        assertThat(PROVIDER_JAR).exists();

        try (GenericContainer<?> keycloak = new GenericContainer<>("quay.io/keycloak/keycloak:" + KEYCLOAK_VERSION)
                .withImagePullPolicy(PullPolicy.defaultPolicy())
                .withCopyFileToContainer(MountableFile.forHostPath(PROVIDER_JAR),
                        "/opt/keycloak/providers/keycloak-kick-identity-provider.jar")
                .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "smoke-admin")
                .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "smoke-password-not-for-production")
                .withExposedPorts(8080)
                .withCommand("start-dev")
                .waitingFor(Wait.forHttp("/realms/master/.well-known/openid-configuration")
                        .forStatusCode(200)
                        .withStartupTimeout(Duration.ofMinutes(3)))) {
            keycloak.start();

            String baseUrl = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
            String adminToken = adminToken(baseUrl);
            HttpResponse<String> response = request(baseUrl + "/admin/realms/master/identity-provider/providers/kick",
                    adminToken);

            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).contains("\"id\":\"kick\"");
            assertThat(response.body()).contains("\"name\":\"Kick\"");
        }
    }

    private static String adminToken(String baseUrl) throws IOException, InterruptedException {
        String form = "grant_type=client_credentials&client_id=admin-cli&username=smoke-admin&password="
                + URLEncoder.encode("smoke-password-not-for-production", StandardCharsets.UTF_8);
        // bootstrap admin login uses resource-owner password grant, not client credentials.
        form = "grant_type=password&client_id=admin-cli&username=smoke-admin&password="
                + URLEncoder.encode("smoke-password-not-for-production", StandardCharsets.UTF_8);
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/realms/master/protocol/openid-connect/token"))
                .timeout(Duration.ofSeconds(30))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        return new com.fasterxml.jackson.databind.ObjectMapper().readTree(response.body()).get("access_token").asText();
    }

    private static HttpResponse<String> request(String url, String bearerToken)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + bearerToken)
                .GET()
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }
}
