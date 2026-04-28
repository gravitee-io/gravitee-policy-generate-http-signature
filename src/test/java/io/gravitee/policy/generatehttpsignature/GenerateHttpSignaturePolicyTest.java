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

import io.gravitee.common.http.HttpMethod;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.buffer.Buffer;
import io.gravitee.gateway.api.http.HttpHeaderNames;
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
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GenerateHttpSignaturePolicyTest {

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
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
    }

    @Test
    void shouldReturnCorrectPolicyId() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);
        assertThat(policy.id()).isEqualTo("generate-http-signature");
    }

    @Test
    void shouldFailOnRequestWhenDateHeaderIsMissingAndNoHeadersConfigured() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .signHeaders(true)
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        HttpPlainRequest request = mock(HttpPlainRequest.class);
        doReturn(request).when(plainContext).request();
        doReturn(httpHeaders).when(request).headers();
        when(httpHeaders.contains(HttpHeaderNames.DATE)).thenReturn(false);
        when(plainContext.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.complete());

        policy.onRequest(plainContext).test().assertComplete();

        ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(ExecutionFailure.class);
        verify(plainContext).interruptWith(failureCaptor.capture());
        assertThat(failureCaptor.getValue().message()).contains("'Date' header is missing");
    }

    @Test
    void shouldFailOnRequestWhenHeadersAreInvalid() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .headers(List.of("X-Required-Header"))
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .signHeaders(true)
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        HttpPlainRequest request = mock(HttpPlainRequest.class);
        doReturn(request).when(plainContext).request();
        doReturn(httpHeaders).when(request).headers();
        when(httpHeaders.containsAllKeys(anyList())).thenReturn(false);
        when(httpHeaders.names()).thenReturn(java.util.Collections.emptySet());
        when(plainContext.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.complete());

        policy.onRequest(plainContext).test().assertComplete();

        ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(ExecutionFailure.class);
        verify(plainContext).interruptWith(failureCaptor.capture());
        assertThat(failureCaptor.getValue().message()).contains("those headers are missing");
    }

    @Test
    void shouldGenerateSignatureOnRequest() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.SIGNATURE)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .signMethod(true)
            .signUri(true)
            .signHeaders(true)
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        HttpPlainRequest request = mock(HttpPlainRequest.class);
        doReturn(request).when(plainContext).request();
        doReturn(httpHeaders).when(request).headers();
        HttpMethod httpMethod = mock(HttpMethod.class);
        doReturn("method").when(httpMethod).name();
        doReturn(httpMethod).when(request).method();
        doReturn("/uri").when(request).uri();
        when(httpHeaders.toSingleValueMap()).thenReturn(Map.of("Date", "01-01-2026"));
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        when(httpHeaders.contains(HttpHeaderNames.DATE)).thenReturn(true);

        policy.onRequest(plainContext).test().assertComplete();

        verify(httpHeaders).set(eq("Signature"), anyString());
    }

    @Test
    void shouldGenerateSignatureOnRequestHeadersAndBody() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.SIGNATURE)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .signMethod(true)
            .signUri(true)
            .signHeaders(true)
            .signPayload(true)
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        HttpPlainRequest request = mock(HttpPlainRequest.class);
        doReturn(request).when(plainContext).request();
        doReturn(httpHeaders).when(request).headers();
        HttpMethod httpMethod = mock(HttpMethod.class);
        doReturn("method").when(httpMethod).name();
        doReturn(httpMethod).when(request).method();
        doReturn("/uri").when(request).uri();
        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(Maybe.just(buffer)).when(request).body();
        when(httpHeaders.toSingleValueMap()).thenReturn(Map.of("Date", "01-01-2026"));
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        when(httpHeaders.contains(HttpHeaderNames.DATE)).thenReturn(true);

        policy.onRequest(plainContext).test().assertComplete();

        verify(httpHeaders).set(eq("Signature"), anyString());
    }

    @Test
    void shouldGenerateSignatureOnHttpResponse() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), anyString());
    }

    @Test
    void shouldGenerateSignatureOnHttpResponseOnHeadersAndBody() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.SIGNATURE)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .signMethod(false)
            .signUri(false)
            .signHeaders(true)
            .signPayload(true)
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(Map.of("Date", "11.03.2026")).when(httpHeaders).toSingleValueMap();
        doReturn(true).when(httpHeaders).contains("Date");
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("Signature"), anyString());
    }

    @Test
    void shouldGenerateSignatureOnHttpResponseOnHeadersMethodAndBody() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.SIGNATURE)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .signMethod(true)
            .signUri(false)
            .signHeaders(true)
            .signPayload(true)
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(Map.of("Date", "11.03.2026")).when(httpHeaders).toSingleValueMap();
        doReturn(true).when(httpHeaders).contains("Date");
        HttpPlainRequest request = mockRequest();
        doReturn(request).when(plainContext).request();
        HttpMethod httpMethod = mock(HttpMethod.class);
        doReturn("method").when(httpMethod).name();
        doReturn(httpMethod).when(request).method();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("Signature"), anyString());
    }

    @Test
    void shouldGenerateSignatureOnHttpResponseOnHeadersMethodUriAndBody() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.SIGNATURE)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .signMethod(true)
            .signUri(true)
            .signHeaders(true)
            .signPayload(true)
            .build();
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(Map.of("Date", "11.03.2026")).when(httpHeaders).toSingleValueMap();
        doReturn(true).when(httpHeaders).contains("Date");
        HttpPlainRequest request = mockRequest();
        doReturn(request).when(plainContext).request();
        HttpMethod httpMethod = mock(HttpMethod.class);
        doReturn("method").when(httpMethod).name();
        doReturn(httpMethod).when(request).method();
        doReturn("/uri").when(request).uri();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("Signature"), anyString());
    }

    @Test
    void shouldGenerateDifferentSignaturesForDifferentPayloads() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload1 = "payload1";
        String payload2 = "payload2";

        when(buffer.toString()).thenReturn(payload1);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        policy.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signature1 = signatureCaptor.getValue();

        reset(httpHeaders);

        when(buffer.toString()).thenReturn(payload2);
        policy.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signature2 = signatureCaptor.getValue();

        assertThat(signature1).isNotEqualTo(signature2);
    }

    @Test
    void shouldFailWhenSecretCannotBeResolved() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        when(buffer.toString()).thenReturn("payload");
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.empty());
        when(plainContext.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.complete());

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(plainContext).interruptWith(any(ExecutionFailure.class));
    }

    @Test
    void shouldGenerateSignatureWithAdditionalHeaders() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .headers(List.of("X-Custom-Header"))
            .headersDelimiter(":")
            .prependHeadersToBody(true)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));
        when(httpHeaders.get("X-Custom-Header")).thenReturn("custom-value");
        when(httpHeaders.toSingleValueMap()).thenReturn(Map.of("X-Custom-Header", "custom-value"));

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), anyString());
    }

    @Test
    void shouldFailWhenRequiredAdditionalHeaderIsMissing() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .headers(List.of("X-Required-Header"))
            .headersDelimiter(":")
            .prependHeadersToBody(true)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        HttpPlainRequest request = mock(HttpPlainRequest.class);
        doReturn(request).when(plainContext).request();
        doReturn(mockResponse(buffer)).when(plainContext).response();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));
        when(httpHeaders.get("X-Required-Header")).thenReturn(null);
        when(plainContext.interruptWith(any(ExecutionFailure.class))).thenReturn(Completable.complete());

        TestObserver<Void> testObserver = policy.onResponse(plainContext).test();

        testObserver.assertComplete();
        ArgumentCaptor<ExecutionFailure> failureCaptor = ArgumentCaptor.forClass(ExecutionFailure.class);
        verify(plainContext).interruptWith(failureCaptor.capture());
        assertThat(failureCaptor.getValue().key()).isEqualTo("HTTP_SIGNATURE_ADDITIONAL_HEADERS_NOT_VALID");
    }

    @Test
    void shouldGenerateValidBase64Signature() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);
        policy.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());

        String signature = signatureCaptor.getValue();
        assertThat(signature).isNotNull();
        int signatureIndex = signature.indexOf("signature="); // The signature should contain the "signature=" part as per the HTTP Signature spec)
        String signatureBase64Part = signature.substring(signatureIndex + "signature=".length()).replaceAll("\"", ""); // Extract the base64 part of the signature and remove any surrounding quotes

        // Verify it's valid base64
        try {
            byte[] decoded = Base64.getDecoder().decode(signatureBase64Part);
            assertThat(decoded).isNotEmpty();
        } catch (IllegalArgumentException e) {
            throw new AssertionError("Signature is not valid base64", e);
        }
    }

    @Test
    void shouldUseDifferentAlgorithms() {
        String payload = "test payload";
        when(buffer.toString()).thenReturn(payload);
        doReturn(mockResponse(buffer)).when(plainContext).response();
        doReturn(mockRequest()).when(plainContext).request();
        when(plainContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        ArgumentCaptor<String> signatureCaptor = ArgumentCaptor.forClass(String.class);

        // Test SHA1
        GenerateHttpSignaturePolicyConfiguration configSHA1 = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA1)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policySHA1 = new GenerateHttpSignaturePolicy(configSHA1);
        policySHA1.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signatureSHA1 = signatureCaptor.getValue();

        reset(httpHeaders);

        // Test SHA256
        GenerateHttpSignaturePolicyConfiguration configSHA256 = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policySHA256 = new GenerateHttpSignaturePolicy(configSHA256);
        policySHA256.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signatureSHA256 = signatureCaptor.getValue();

        reset(httpHeaders);

        // Test SHA512
        GenerateHttpSignaturePolicyConfiguration configSHA512 = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .algorithm(Algorithm.HMAC_SHA512)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();
        GenerateHttpSignaturePolicy policySHA512 = new GenerateHttpSignaturePolicy(configSHA512);
        policySHA512.onResponse(plainContext).test().assertComplete();
        verify(httpHeaders).set(eq("X-HMAC-Signature"), signatureCaptor.capture());
        String signatureSHA512 = signatureCaptor.getValue();

        // All signatures should be different
        assertThat(signatureSHA1).isNotEqualTo(signatureSHA256);
        assertThat(signatureSHA256).isNotEqualTo(signatureSHA512);
        assertThat(signatureSHA1).isNotEqualTo(signatureSHA512);
    }

    @Test
    void shouldGenerateSignatureOnMessageResponse() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "message payload";
        when(message.content()).thenReturn(Buffer.buffer(payload));
        when(message.headers()).thenReturn(httpHeaders);

        HttpMessageRequest request = mock(HttpMessageRequest.class);

        HttpMessageResponse response = mockMessageResponse();
        when(messageContext.response()).thenReturn(response);

        when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));

        ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor = ArgumentCaptor.forClass(Function.class);

        policy.onMessageResponse(messageContext).test().assertComplete();

        verify(response).onMessage(onMessageCaptor.capture());
        onMessageCaptor.getValue().apply(message).test().assertComplete();

        verify(httpHeaders).set(eq("X-HMAC-Signature"), anyString());
    }

    @Test
    void shouldFailWhenSecretCannotBeResolvedOnMessageResponse() {
        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "message payload";
        when(message.content()).thenReturn(Buffer.buffer(payload));
        when(message.headers()).thenReturn(httpHeaders);

        when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.empty());
        when(messageContext.interruptMessageWith(any(ExecutionFailure.class))).thenReturn(Maybe.empty());

        HttpMessageResponse response = mockMessageResponse();
        when(messageContext.response()).thenReturn(response);

        ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor = ArgumentCaptor.forClass(Function.class);

        policy.onMessageResponse(messageContext).test().assertComplete();

        verify(response).onMessage(onMessageCaptor.capture());
        onMessageCaptor.getValue().apply(message).test().assertComplete();

        verify(messageContext).interruptMessageWith(any(ExecutionFailure.class));
    }

    @Test
    void shouldGenerateSignatureWithAdditionalHeadersOnMessageResponse() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder()
            .scheme(HttpSignatureScheme.CUSTOM_HEADER)
            .headers(List.of("X-Custom-Header"))
            .headersDelimiter(":")
            .prependHeadersToBody(true)
            .algorithm(Algorithm.HMAC_SHA256)
            .keyId("test-key")
            .secret("test-secret")
            .targetSignatureHeader("X-HMAC-Signature")
            .build();

        GenerateHttpSignaturePolicy policy = new GenerateHttpSignaturePolicy(configuration);

        String payload = "message payload";
        when(message.content()).thenReturn(Buffer.buffer(payload));
        when(message.headers()).thenReturn(httpHeaders);

        HttpMessageResponse response = mockMessageResponse();
        when(messageContext.response()).thenReturn(response);

        when(messageContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.eval("test-secret", String.class)).thenReturn(Maybe.just("test-secret"));
        when(httpHeaders.get("X-Custom-Header")).thenReturn("custom-value");
        when(httpHeaders.toSingleValueMap()).thenReturn(Map.of("X-Custom-Header", "custom-value"));

        ArgumentCaptor<Function<Message, Maybe<Message>>> onMessageCaptor = ArgumentCaptor.forClass(Function.class);

        policy.onMessageResponse(messageContext).test().assertComplete();

        verify(response).onMessage(onMessageCaptor.capture());
        onMessageCaptor.getValue().apply(message).test().assertComplete();

        verify(httpHeaders).set(eq("X-HMAC-Signature"), anyString());
    }

    // Helper methods

    private HttpPlainResponse mockResponse(Buffer buffer) {
        HttpPlainResponse response = mock(HttpPlainResponse.class);
        doReturn(Maybe.just(buffer)).when(response).body();
        doReturn(httpHeaders).when(response).headers();
        return response;
    }

    private HttpPlainRequest mockRequest() {
        HttpPlainRequest request = mock(HttpPlainRequest.class);
        return request;
    }

    private HttpMessageResponse mockMessageResponse() {
        HttpMessageResponse response = mock(HttpMessageResponse.class);
        doAnswer(invocation -> Completable.complete())
            .when(response)
            .onMessage(any());
        return response;
    }
}
