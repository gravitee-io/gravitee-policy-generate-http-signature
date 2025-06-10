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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.definition.model.ExecutionMode;
import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.util.List;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.tomitribe.auth.signatures.Signature;

@GatewayTest(v2ExecutionMode = ExecutionMode.V3)
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GenerateHttpSignaturePolicyV3IntegrationTest
    extends AbstractPolicyTest<GenerateHttpSignaturePolicy, GenerateHttpSignaturePolicyConfiguration> {

    @Test
    @DeployApi("/apis/authorization-with-missing-header.json")
    void should_make_policy_chain_fail_because_invalid_headers(HttpClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        client
            .rxRequest(HttpMethod.GET, "/generate-authorization")
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(400);
                return response.toFlowable();
            })
            .test()
            .awaitDone(5, SECONDS)
            .assertComplete()
            .assertValue(responseBody -> {
                assertThat(responseBody).hasToString("Unable to generate HTTP Signature: those headers are missing [Required header]");
                return true;
            })
            .assertNoErrors();
    }

    @Test
    @DeployApi("/apis/authorization-with-created-and-expires.json")
    void should_make_policy_chain_fail_from_missing_date_header(HttpClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        client
            .rxRequest(HttpMethod.GET, "/generate-authorization")
            .flatMap(HttpClientRequest::rxSend)
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(400);
                return response.toFlowable();
            })
            .test()
            .awaitDone(5, SECONDS)
            .assertComplete()
            .assertValue(responseBody -> {
                assertThat(responseBody).hasToString("Unable to generate HTTP Signature: 'Date' header is missing");
                return true;
            })
            .assertNoErrors();
    }

    @Test
    @DeployApi("/apis/authorization-with-broken-el.json")
    void should_make_policy_chain_fail_because_of_an_exception_during_signing_process(HttpClient client) {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        client
            .rxRequest(HttpMethod.GET, "/generate-authorization")
            .flatMap(request -> {
                request.putHeader("Date", "Thu, 01 Jan 1970 00:00:00 GMT");
                return request.rxSend();
            })
            .flatMapPublisher(response -> {
                assertThat(response.statusCode()).isEqualTo(500);
                return response.toFlowable();
            })
            .test()
            .awaitDone(5, SECONDS)
            .assertComplete()
            .assertNoErrors();
    }

    @ParameterizedTest
    @CsvSource({ "/generate-signature, Signature", "/generate-authorization, Authorization" })
    @DeployApi({ "/apis/signature-with-created-and-expires.json", "/apis/authorization-with-created-and-expires.json" })
    void should_properly_generate_signature(String requestURI, String headerName, HttpClient client) {
        // given
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        // when
        client
            .rxRequest(HttpMethod.GET, requestURI)
            .flatMap(request -> {
                request.putHeader("Date", "Mon, 09 Jun 2025 15:00:00 GMT");
                return request.rxSend();
            })
            .test()
            .awaitDone(5, SECONDS)
            .assertComplete()
            .assertNoErrors();

        // then
        List<LoggedRequest> requests = wiremock.findAll(getRequestedFor(urlEqualTo("/endpoint")));
        assertThat(requests).hasSize(1);

        LoggedRequest backendRequest = requests.get(0);
        assertThat(backendRequest).isNotNull();

        Signature authorizationHeader = Signature.fromString(backendRequest.getHeader(headerName));

        long createdSeconds = authorizationHeader.getSignatureCreation().toInstant().getEpochSecond();
        long expiresSeconds = authorizationHeader.getSignatureExpiration().toInstant().getEpochSecond();
        long expirationDelta = expiresSeconds - createdSeconds;

        assertThat(expirationDelta).isEqualTo(2);
        assertThat(authorizationHeader.getKeyId()).isEqualTo("keyId");
        assertThat(authorizationHeader.getAlgorithm().getJvmName()).isEqualTo("HmacSHA256");
        assertThat(authorizationHeader.getSignature()).isNotBlank();
        assertThat(authorizationHeader.getHeaders()).containsExactlyInAnyOrder("(created)", "(expires)");
    }

    @ParameterizedTest
    @CsvSource({ "/generate-signature, Signature", "/generate-authorization, Authorization" })
    @DeployApi({ "/apis/authorization-with-no-created-and-expires.json", "/apis/signature-with-no-created-and-expires.json" })
    void should_properly_generate_signature_with_no_created_and_expires(String requestURI, String headerName, HttpClient client) {
        // given
        wiremock.stubFor(get("/endpoint").willReturn(aResponse().withStatus(200)));

        // when
        client
            .rxRequest(HttpMethod.GET, requestURI)
            .flatMap(request -> {
                request.putHeader("Date", "Mon, 09 Jun 2025 15:00:00 GMT");
                return request.rxSend();
            })
            .test()
            .awaitDone(5, SECONDS)
            .assertComplete()
            .assertNoErrors();

        // then
        List<LoggedRequest> requests = wiremock.findAll(getRequestedFor(urlEqualTo("/endpoint")));
        assertThat(requests).hasSize(1);

        LoggedRequest backendRequest = requests.get(0);
        assertThat(backendRequest).isNotNull();

        Signature authorizationHeader = Signature.fromString(backendRequest.getHeader(headerName));

        assertThat(authorizationHeader.getSignatureCreation()).isNull();
        assertThat(authorizationHeader.getSignatureExpiration()).isNull();
        assertThat(authorizationHeader.getKeyId()).isEqualTo("keyId");
        assertThat(authorizationHeader.getAlgorithm().getJvmName()).isEqualTo("HmacSHA256");
        assertThat(authorizationHeader.getSignature()).isNotBlank();
        assertThat(authorizationHeader.getHeaders()).contains("host");
    }
}
