/*
 * Copyright the keycloak-kick-identity-provider contributors.
 *
 * Licensed under the MIT License. See LICENSE in the project root.
 */
package io.github.enhancerapp.keycloak.kick.support;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;

/**
 * A loopback HTTP server used to stand in for the Kick API.
 *
 * <p>Preferred over a mocking framework for the transport layer: it exercises the real Apache
 * HTTP client, real header encoding and real form encoding, so a test that asserts "the token
 * request carried a code_verifier" is asserting what actually goes on the wire.
 */
public final class StubHttpServer implements AutoCloseable {

    /** A recorded inbound request. */
    public record Recorded(String method, String path, Map<String, List<String>> headers, String body) {

        public String header(String name) {
            return headers().entrySet().stream()
                    .filter(entry -> entry.getKey().equalsIgnoreCase(name))
                    .map(Map.Entry::getValue)
                    .filter(values -> !values.isEmpty())
                    .map(values -> values.get(0))
                    .findFirst()
                    .orElse(null);
        }

        /** @return the body parsed as {@code application/x-www-form-urlencoded}. */
        public Map<String, String> formParams() {
            return FormCodec.parse(body());
        }
    }

    private final HttpServer server;
    private final List<Recorded> requests = new CopyOnWriteArrayList<>();
    private final AtomicInteger status = new AtomicInteger(200);
    private volatile String responseBody = "{}";
    private volatile String contentType = "application/json";
    private volatile long delayMillis;

    public StubHttpServer() {
        try {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.createContext("/", exchange -> {
            byte[] requestBody;
            try (InputStream in = exchange.getRequestBody()) {
                requestBody = in.readAllBytes();
            }
            requests.add(new Recorded(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    copyHeaders(exchange.getRequestHeaders()),
                    new String(requestBody, StandardCharsets.UTF_8)));

            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            byte[] payload = responseBody.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", contentType);
            exchange.sendResponseHeaders(status.get(), payload.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(payload);
            }
        });
        server.start();
    }

    private static Map<String, List<String>> copyHeaders(Headers headers) {
        return Map.copyOf(headers);
    }

    public String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    public String url(String path) {
        return baseUrl() + path;
    }

    public StubHttpServer respondWith(int statusCode, String body) {
        this.status.set(statusCode);
        this.responseBody = body;
        return this;
    }

    public StubHttpServer respondWith(int statusCode, String body, String contentType) {
        this.contentType = contentType;
        return respondWith(statusCode, body);
    }

    /** Delays the response so a client-side socket timeout can be observed. */
    public StubHttpServer delayResponseBy(long millis) {
        this.delayMillis = millis;
        return this;
    }

    public List<Recorded> requests() {
        return List.copyOf(requests);
    }

    public Recorded lastRequest() {
        if (requests.isEmpty()) {
            throw new AssertionError("no request was received");
        }
        return requests.get(requests.size() - 1);
    }

    public int requestCount() {
        return requests.size();
    }

    @Override
    public void close() {
        server.stop(0);
    }
}
