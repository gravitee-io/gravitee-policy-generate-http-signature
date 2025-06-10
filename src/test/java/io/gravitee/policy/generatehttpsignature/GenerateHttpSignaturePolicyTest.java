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
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.gravitee.common.http.HttpMethod;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatehttpsignature.configuration.Algorithm;
import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.gravitee.policy.generatehttpsignature.configuration.HttpSignatureScheme;
import io.gravitee.reporter.api.http.Metrics;
import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

@ExtendWith(MockitoExtension.class)
class GenerateHttpSignaturePolicyTest {

    private GenerateHttpSignaturePolicy cut;

    @Mock
    private GenerateHttpSignaturePolicyConfiguration configuration;

    @BeforeEach
    void setUp() {
        cut = new GenerateHttpSignaturePolicy(configuration);
    }

    @Test
    @DisplayName("Should make policy chain fail because of invalid headers")
    void shouldFailChain_invalidHeaders() {
        final Request request = mock(Request.class);
        final Response response = mock(Response.class);
        final ExecutionContext executionContext = mock(ExecutionContext.class);
        final PolicyChain policyChain = mock(PolicyChain.class);

        when(configuration.getHeaders()).thenReturn(List.of("Host"));
        when(request.headers()).thenReturn(buildHttpHeadersFromList(List.of("Date")));

        cut.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any());
    }

    @Test
    @DisplayName("Should make policy chain fail because of an exception during signing process")
    void shouldFail_unableToSign() throws IOException {
        final Request request = mock(Request.class);
        final Response response = mock(Response.class);
        final ExecutionContext context = mock(ExecutionContext.class);
        final PolicyChain chain = mock(PolicyChain.class);
        final TemplateEngine templateEngine = mock(TemplateEngine.class);
        final GenerateHttpSignaturePolicy spy = spy(cut);
        final Signer signer = mock(Signer.class);

        when(configuration.getHeaders()).thenReturn(List.of("Host"));
        when(configuration.getAlgorithm()).thenReturn(Algorithm.HMAC_SHA256);
        when(configuration.isCreated()).thenReturn(true);
        when(configuration.isExpires()).thenReturn(true);
        when(configuration.getValidityDuration()).thenReturn(2L);
        when(configuration.getKeyId()).thenReturn("keyId");

        doReturn(signer).when(spy).buildSigner(any(), any());
        when(signer.sign(any(), any(), any())).thenThrow(new IOException("exception-message"));

        final Metrics metrics = Metrics.on(System.currentTimeMillis()).build();

        when(request.headers()).thenReturn(buildHttpHeadersFromList(List.of("Date", "Host")));
        when(request.metrics()).thenReturn(metrics);
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");
        when(context.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.evalNow(eq("keyId"), any())).thenReturn("keyId");

        spy.onRequest(request, response, context, chain);

        assertThat(metrics.getMessage()).isEqualTo("exception-message");
        verify(chain, times(1)).failWith(any());
        verify(chain, never()).doNext(request, response);
    }

    @Test
    @DisplayName("Should execute policy properly")
    public void shouldDoNext() {
        final Request request = mock(Request.class);
        final Response response = mock(Response.class);
        final ExecutionContext context = mock(ExecutionContext.class);
        final PolicyChain chain = mock(PolicyChain.class);
        final TemplateEngine templateEngine = mock(TemplateEngine.class);

        when(configuration.getHeaders()).thenReturn(List.of("Host"));
        when(configuration.getAlgorithm()).thenReturn(Algorithm.HMAC_SHA256);
        when(configuration.isCreated()).thenReturn(true);
        when(configuration.isExpires()).thenReturn(true);
        when(configuration.getValidityDuration()).thenReturn(2L);
        when(configuration.getKeyId()).thenReturn("keyId");
        when(configuration.getSecret()).thenReturn("secret");

        when(request.headers()).thenReturn(buildHttpHeadersFromList(List.of("Date", "Host")));
        when(request.method()).thenReturn(HttpMethod.GET);
        when(request.path()).thenReturn("/my/api");
        when(context.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.evalNow(eq("keyId"), any())).thenReturn("keyId");
        when(templateEngine.evalNow(eq("secret"), any())).thenReturn("keyId");

        cut.onRequest(request, response, context, chain);

        verify(chain, times(1)).doNext(request, response);
    }

    @ParameterizedTest
    @MethodSource("provideCheckConfigureHeadersData")
    @DisplayName("Should check if the request's header are valid regarding policy's configuration and Signature minimal requirements")
    void shouldCheckConfiguredHeaders(List<String> requestHeaders, List<String> configuredHeaders, String errorMessage) {
        final HttpHeaders httpHeaders = buildHttpHeadersFromList(requestHeaders);

        final String result = cut.checkHeaders(httpHeaders, configuredHeaders);

        if (errorMessage == null) {
            assertThat(result).isNull();
        } else {
            assertThat(result).contains(errorMessage);
        }
    }

    @ParameterizedTest
    @CsvSource(value = { "AUTHORIZATION,Authorization,Signature signatureContent", "SIGNATURE,Signature,signatureContent" })
    @DisplayName("Should add the correct header to request depending on HTTP Signature Scheme configuration")
    void shouldSetSignatureHeader(String httpSignatureScheme, String expectedHeaderKey, String expectedHeaderValue) {
        final Signature signature = mock(Signature.class);
        final Request request = mock(Request.class);
        final HttpHeaders httpHeaders = HttpHeaders.create();

        when(request.headers()).thenReturn(httpHeaders);
        when(signature.toString()).thenReturn("Signature signatureContent");
        when(configuration.getScheme()).thenReturn(HttpSignatureScheme.valueOf(httpSignatureScheme));

        cut.setSignatureHeader(request, signature);

        Assertions.assertTrue(request.headers().contains(expectedHeaderKey));
        assertThat(request.headers().getAll(expectedHeaderKey)).hasSize(1);
        assertThat(request.headers().get(expectedHeaderKey)).isEqualTo(expectedHeaderValue);
    }

    /**
     * Provide a stream of Arguments for testing checkHeaders function.
     *
     * @return a Stream of Arguments composed of
     * - A list of String representing the request's headers
     * - A list of String representing the policy configurations's headers
     * - A partial string that have to be contained by the error message, null if should not be in error.
     */
    private static Stream<Arguments> provideCheckConfigureHeadersData() {
        return Stream.of(
            Arguments.of(List.of(), List.of("Host"), "[Host]"),
            Arguments.of(List.of("Accept-Encoding", "X-Gravitee-Header"), List.of("Host", "Accept"), "[Host, Accept]"),
            Arguments.of(List.of("Host"), List.of("Host"), null),
            Arguments.of(List.of("Host"), List.of(), "'Date' header is missing"),
            Arguments.of(List.of("Date"), List.of(), null)
        );
    }

    private HttpHeaders buildHttpHeadersFromList(List<String> requestHeaders) {
        final HttpHeaders httpHeaders = HttpHeaders.create();
        requestHeaders.forEach(header -> httpHeaders.set(header, ""));
        return httpHeaders;
    }
}
