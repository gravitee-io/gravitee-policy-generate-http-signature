/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
package io.gravitee.policy.generatehttpsignature;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.*;
import io.gravitee.gateway.reactive.api.message.Message;
import io.gravitee.policy.generatehttpsignature.configuration.Algorithm;
import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.gravitee.policy.generatehttpsignature.configuration.HttpSignatureScheme;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import io.reactivex.rxjava3.observers.TestObserver;
import java.security.Key;
import java.util.*;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

@ExtendWith(MockitoExtension.class)
@DisplayName("Http Signature Generator Policy - Integration Tests")
class GenerateHttpSignaturePolicyIntegrationTest {

    @Mock
    private HttpPlainExecutionContext plainContext;

    @Mock
    private HttpMessageExecutionContext messageContext;

    @Mock
    private TemplateEngine templateEngine;

    @Mock
    private HttpHeaders httpHeaders;

    @Mock
    private Message message;

    @Mock
    private Buffer buffer;

    private GenerateHttpSignaturePolicyConfiguration configuration;

    @BeforeEach
    void setUp() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
    }

    @Test
    @DisplayName("Should generate correct HMAC signature for simple payload")
    void shouldGenerateCorrectSignatureForSimplePayload() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"event\":\"user.created\",\"userId\":123}";
        String secret = "my-secret-key";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();
        String expectedSignature = generateExpectedSignature(configuration.keyId(), payload, secret, Algorithm.HMAC_SHA256);

        assertThat(generatedSignature).isEqualTo(expectedSignature);
    }

    @Test
    @DisplayName("Should generate correct HMAC signature with timestamp and expiry")
    void shouldGenerateCorrectSignatureWithTimestampAndExpiry() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .created(true)
            .expires(true)
            .validityDuration(5L)
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"event\":\"user.created\",\"userId\":123}";
        String secret = "my-secret-key";
        String keyId = "my-key-id";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequestWithTimestamp()).when(plainContext).request();

        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();

        System.out.println("Generated Signature: " + generatedSignature);
        assertThat(generatedSignature.contains("created=")).isTrue();
        assertThat(generatedSignature.contains("expires=")).isTrue();
        assertThat(generatedSignature.contains("headers=\"(created) (expires)\"")).isTrue();
    }

    @Test
    @DisplayName("Should generate signature with additional headers prepended to payload")
    void shouldGenerateSignatureWithAdditionalHeaders() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .headers(Arrays.asList("X-Request-ID", "X-Timestamp"))
            .headersDelimiter(".")
            .prependHeadersToBody(true)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"data\":\"test\"}";
        String secret = "my-secret-key";
        String requestId = "req-12345";
        String timestamp = "2025-01-15T10:30:00Z";
        Map<String, String> headersMap = new LinkedHashMap<>();
        headersMap.put("X-Request-ID", requestId);
        headersMap.put("X-Timestamp", timestamp);

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));
        when(httpHeaders.get("X-Request-ID")).thenReturn(requestId);
        when(httpHeaders.get("X-Timestamp")).thenReturn(timestamp);
        when(httpHeaders.toSingleValueMap()).thenReturn(headersMap);
        when(httpHeaders.names()).thenReturn(headersMap.keySet());

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();
        String expectedPayload = requestId + "." + timestamp + "." + payload;
        String expectedSignature = generateExpectedSignature(configuration.keyId(), expectedPayload, secret, Algorithm.HMAC_SHA256);

        assertThat(generatedSignature).isEqualTo(expectedSignature);
    }

    @Test
    @DisplayName("Should handle large JSON payloads")
    void shouldHandleLargePayloads() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        StringBuilder largePayload = new StringBuilder("{\"data\":[");
        for (int i = 0; i < 1000; i++) {
            if (i > 0) largePayload.append(",");
            largePayload.append("{\"id\":").append(i).append(",\"name\":\"item").append(i).append("\"}");
        }
        largePayload.append("]}");

        String payload = largePayload.toString();
        String secret = "my-secret-key";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();
        assertThat(generatedSignature).isNotNull();
        assertThat(generatedSignature).hasSize(109); // SHA256 base64 is 44 chars
    }

    @Test
    @DisplayName("Should generate different signatures for SHA1, SHA256, and SHA512")
    void shouldGenerateDifferentSignaturesForDifferentAlgorithms() {
        String payload = "{\"event\":\"test\"}";
        String keyId = "my-key-id";
        String secret = "my-secret-key";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);

        // SHA1
        GenerateHttpSignaturePolicyConfiguration configSHA1 = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA1)
            .keyId(keyId)
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policySHA1 = new GenerateHttpSignaturePolicy(configSHA1);
        policySHA1.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signatureSHA1 = signatureCaptor.getValue();
        String expectedSHA1 = generateExpectedSignature(configuration.keyId(), payload, secret, Algorithm.HMAC_SHA1);
        assertThat(signatureSHA1).isEqualTo(expectedSHA1);
        assertThat(signatureSHA1).hasSize(91); // SHA1 base64 is 28 chars

        reset(httpHeaders);

        // SHA256
        GenerateHttpSignaturePolicyConfiguration configSHA256 = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId(keyId)
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policySHA256 = new GenerateHttpSignaturePolicy(configSHA256);
        policySHA256.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signatureSHA256 = signatureCaptor.getValue();
        String expectedSHA256 = generateExpectedSignature(configuration.keyId(), payload, secret, Algorithm.HMAC_SHA256);
        assertThat(signatureSHA256).isEqualTo(expectedSHA256);
        assertThat(signatureSHA256).hasSize(109); // SHA256 base64 is 44 chars

        reset(httpHeaders);

        // SHA512
        GenerateHttpSignaturePolicyConfiguration configSHA512 = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA512)
            .keyId(keyId)
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policySHA512 = new GenerateHttpSignaturePolicy(configSHA512);
        policySHA512.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signatureSHA512 = signatureCaptor.getValue();
        String expectedSHA512 = generateExpectedSignature(configuration.keyId(), payload, secret, Algorithm.HMAC_SHA512);
        assertThat(signatureSHA512).isEqualTo(expectedSHA512);
        assertThat(signatureSHA512).hasSize(153); // SHA512 base64 is 88 chars

        assertThat(signatureSHA1).isNotEqualTo(signatureSHA256);
        assertThat(signatureSHA256).isNotEqualTo(signatureSHA512);
    }

    @Test
    @DisplayName("Should use custom header name for signature")
    void shouldUseCustomHeaderName() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("my-secret-key")
            .targetSignatureHeader("X-Custom-Signature-Header")
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"test\":\"data\"}";
        String secret = "my-secret-key";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-Custom-Signature-Header"), anyString());
        verify(httpHeaders, never()).set(eq("X-HMAC-Signature"), anyString());
    }

    @Test
    @DisplayName("Should resolve secret from secret manager and generate valid signature")
    void shouldResolveSecretFromSecretManagerAndGenerateSignature() {
        // Configure policy to use secret manager expression
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("{#secrets.get('/dev/secret/gravitee/secrets:test')}")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"event\":\"webhook.test\",\"data\":\"example\"}";
        String actualSecretValue = "my-vault-secret-key";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);

        // Mock the secret manager resolution
        when(templateEngine.eval("{#secrets.get('/dev/secret/gravitee/secrets:test')}", String.class)).thenReturn(
            Maybe.just(actualSecretValue)
        );

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);

        // Execute the policy
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        // Verify execution completed successfully
        testObserver.assertComplete();

        // Capture the generated signature
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();
        assertThat(generatedSignature).isNotNull();
        assertThat(generatedSignature).isNotEmpty();

        // Verify the signature is valid by recalculating it
        String expectedSignature = generateExpectedSignature(configuration.keyId(), payload, actualSecretValue, Algorithm.HMAC_SHA256);
        assertThat(generatedSignature).isEqualTo(expectedSignature);

        // Verify the secret was correctly resolved from the expression
        verify(templateEngine).eval("{#secrets.get('/dev/secret/gravitee/secrets:test')}", String.class);

        // Verify signature can be validated by external system
        boolean isValid = verifySignature(payload, actualSecretValue, generatedSignature, Algorithm.HMAC_SHA256);
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Should handle EL template expressions in secret")
    void shouldHandleTemplateExpressionInSecret() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("{#context.attributes['secret-key']}")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"data\":\"test\"}";
        String resolvedSecret = "resolved-secret-from-context";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("{#context.attributes['secret-key']}", String.class)).thenReturn(Maybe.just(resolvedSecret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();
        String expectedSignature = generateExpectedSignature(configuration.keyId(), payload, resolvedSecret, Algorithm.HMAC_SHA256);
        assertThat(generatedSignature).isEqualTo(expectedSignature);
    }

    @Test
    @DisplayName("Should fail when secret cannot be resolved")
    void shouldFailWhenSecretCannotBeResolved() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("{#context.attributes['missing-key']}")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        when(buffer.toString()).thenReturn("payload");
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        doReturn(mockResponse(buffer)).when(plainContext).response();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("{#context.attributes['missing-key']}", String.class)).thenReturn(Maybe.empty());
        when(plainContext.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.complete());

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(ExecutionFailure.class);
        verify(plainContext).interruptWith(failureCaptor.capture());
        assertThat(failureCaptor.getValue().key()).isEqualTo("HTTP_SIGNATURE_IMPOSSIBLE_GENERATION");
    }

    @Test
    @DisplayName("Should fail when required additional header is missing")
    void shouldFailWhenAdditionalHeaderIsMissing() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .headers(List.of("X-Required-Header"))
            .headersDelimiter(":")
            .prependHeadersToBody(true)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("my-key-id")
            .secret("my-secret-key")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        when(buffer.toString()).thenReturn("payload");
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        doReturn(mockResponse(buffer)).when(plainContext).response();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("my-secret-key", String.class)).thenReturn(Maybe.just("my-secret-key"));
        when(httpHeaders.get("X-Required-Header")).thenReturn(null);
        when(plainContext.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.complete());

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(ExecutionFailure.class);
        verify(plainContext).interruptWith(failureCaptor.capture());
        assertThat(failureCaptor.getValue().key()).isEqualTo("HTTP_SIGNATURE_ADDITIONAL_HEADERS_NOT_VALID");
    }

    @Test
    @DisplayName("Should handle Unicode characters in payload")
    void shouldHandleUnicodeInPayload() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "{\"message\":\"Hello 世界 🌍\"}";
        String secret = "my-secret-key";
        String keyId = "my-key-id";

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();
        String expectedSignature = generateExpectedSignature(configuration.keyId(), payload, secret, Algorithm.HMAC_SHA256);
        assertThat(generatedSignature).isEqualTo(expectedSignature);
    }

    @Test
    @DisplayName("Should verify signature can be validated by external system")
    void shouldProduceVerifiableSignature() {
        String payload = "{\"event\":\"user.created\",\"userId\":123}";
        String secret = "shared-secret-key";
        String keyId = "my-key-id";
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId(keyId)
            .secret(secret)
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mock(HttpPlainRequest.class)).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval(secret, String.class)).thenReturn(Maybe.just(secret));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        policy.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String generatedSignature = signatureCaptor.getValue();

        // Simulate external system verification
        boolean isValid = verifySignature(payload, secret, generatedSignature, Algorithm.HMAC_SHA256);
        assertThat(isValid).isTrue();
    }

    // Helper methods

    private HttpPlainResponse mockResponse(Buffer buffer) {
        HttpPlainResponse response = mock(HttpPlainResponse.class);
        doReturn(Maybe.just(buffer)).when(response).body();
        doReturn(httpHeaders).when(response).headers();
        return response;
    }

    private HttpPlainRequest mockRequestWithTimestamp() {
        HttpPlainRequest request = mock(HttpPlainRequest.class);
        doReturn(1l).when(request).timestamp();
        return request;
    }

    private HttpMessageResponse mockMessageResponse() {
        HttpMessageResponse response = mock(HttpMessageResponse.class);
        doAnswer(invocation -> Completable.complete())
            .when(response)
            .onMessage(any());
        return response;
    }

    private String generateExpectedSignature(String keyId, String payload, String secret, Algorithm algorithm) {
        return generateExpectedSignature(keyId, payload, secret, algorithm, false, false, 0L);
    }

    private String generateExpectedSignature(
        String keyId,
        String payload,
        String secret,
        Algorithm algorithm,
        boolean timestamp,
        boolean expires,
        long validityDuration
    ) {
        try {
            List<String> headers = new ArrayList<>(httpHeaders.names().stream().toList());

            if (timestamp) {
                headers.add("(created)");
            }
            if (expires) {
                headers.add("(expires)");
            }

            Signature signatureFromConfiguration = new Signature(
                keyId,
                null,
                algorithm.getAlg(),
                null,
                null,
                headers,
                expires ? (validityDuration * 1000) : null,
                timestamp ? 1L : null,
                null,
                false
            );
            final Key key = new SecretKeySpec(secret.getBytes(), signatureFromConfiguration.getAlgorithm().getJvmName());
            Signer signer = new Signer(key, signatureFromConfiguration);
            Signature signature = signer.signWithPayload("method", "uri", httpHeaders.toSingleValueMap(), payload);
            return signature.toString().substring(10); // Remove the "Signature " part of the signature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate expected signature", e);
        }
    }

    private boolean verifySignature(String payload, String secret, String receivedSignature, Algorithm algorithm) {
        String expectedSignature = generateExpectedSignature(configuration.keyId(), payload, secret, algorithm);
        return expectedSignature.equals(receivedSignature);
    }
}
