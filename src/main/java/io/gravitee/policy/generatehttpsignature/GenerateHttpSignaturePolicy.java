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

import static org.springframework.util.CollectionUtils.isEmpty;

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.gravitee.policy.generatehttpsignature.configuration.HttpSignatureScheme;
import java.io.IOException;
import java.security.Key;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GenerateHttpSignaturePolicy {

    private static final Logger logger = LoggerFactory.getLogger(GenerateHttpSignaturePolicy.class);

    private static final String HTTP_SIGNATURE_IMPOSSIBLE_GENERATION = "HTTP_SIGNATURE_IMPOSSIBLE_GENERATION";
    private static final String ERROR_MESSAGE = "Unable to generate HTTP Signature:";

    private final GenerateHttpSignaturePolicyConfiguration configuration;

    public GenerateHttpSignaturePolicy(GenerateHttpSignaturePolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext context, PolicyChain chain) {
        HttpHeaders requestHeaders = HttpHeaders.create(request.headers());
        List<String> configuredHeaders = new ArrayList<>(configuration.getHeaders());

        final String checkHeadersErrorMessage = checkHeaders(requestHeaders, configuredHeaders);
        if (checkHeadersErrorMessage != null) {
            logger.warn(checkHeadersErrorMessage);
            chain.failWith(PolicyResult.failure(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION, 400, checkHeadersErrorMessage));
            return;
        }

        if (configuration.isCreated()) {
            configuredHeaders.add("(created)");
        }

        if (configuration.isExpires()) {
            configuredHeaders.add("(expires)");
        }

        final Signature signatureFromConfiguration = buildSignatureFromConfiguration(context, request, configuredHeaders);

        final Signer signer = buildSigner(context, signatureFromConfiguration);
        final Signature signature;

        try {
            signature = signer.sign(request.method().name().toLowerCase(), request.path(), requestHeaders.toSingleValueMap());
        } catch (IOException e) {
            final String errorMessage = String.format("%s %s", ERROR_MESSAGE, e.getMessage());
            logger.warn(errorMessage);
            request.metrics().setMessage(e.getMessage());
            chain.failWith(PolicyResult.failure(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION, 400, errorMessage));
            return;
        }

        setSignatureHeader(request, signature);

        chain.doNext(request, response);
    }

    /**
     * Validate the request by verifying it has the headers mentioned in policy's configuration.
     * @param headers the incoming request's headers.
     * @param configuredHeaders the headers from policy's configuration.
     * @return the error message if headers are not valid, null if it's ok
     *
     */
    String checkHeaders(HttpHeaders headers, List<String> configuredHeaders) {
        if (!isEmpty(configuredHeaders)) {
            if (!headers.containsAllKeys(configuredHeaders)) {
                final ArrayList<String> missingHeaders = new ArrayList<>(configuredHeaders);
                missingHeaders.removeAll(headers.names());

                return String.format(
                    "%s those headers are missing %s",
                    ERROR_MESSAGE,
                    missingHeaders.stream().collect(Collectors.joining(", ", "[", "]"))
                );
            }
        } else if (!headers.contains(HttpHeaderNames.DATE)) {
            return String.format("%s 'Date' header is missing", ERROR_MESSAGE);
        }

        return null;
    }

    /**
     * Build signature from policy configuration.
     * @param context the API execution context
     * @param configuredHeaders the headers to add to signature
     * @return the signature
     */
    Signature buildSignatureFromConfiguration(ExecutionContext context, Request request, List<String> configuredHeaders) {
        final String keyId = context.getTemplateEngine().evalNow(configuration.getKeyId(), String.class);
        return new Signature(
            keyId,
            null,
            configuration.getAlgorithm().getAlg(),
            null,
            null,
            configuredHeaders,
            configuredHeaders.contains("(expires)") ? configuration.getValidityDuration() * 1000 : null,
            configuredHeaders.contains("(created)") ? request.timestamp() : null,
            null
        );
    }

    /**
     * Build a signer based on the configured signature and the secret from policy configuration.
     * @param context the API execution context
     * @param signature the formerly created signature from configuration
     * @return the signer able to create the signature with provided secret and algorithm
     */
    Signer buildSigner(ExecutionContext context, Signature signature) {
        String secret = context.getTemplateEngine().evalNow(configuration.getSecret(), String.class);
        final Key key = new SecretKeySpec(secret.getBytes(), signature.getAlgorithm().getJvmName());
        return new Signer(key, signature);
    }

    /**
     * Add the HTTP Signature to the request's headers regarding the policy configuration Http Signature Scheme
     * @param request the request on which add the header
     * @param signature the signature to use in the header
     */
    void setSignatureHeader(Request request, Signature signature) {
        if (HttpSignatureScheme.SIGNATURE.equals(configuration.getScheme())) {
            final String substring = signature.toString().substring(10); // Remove the "Signature " part of the signature
            // https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.section.4.1
            request.headers().set("Signature", substring);
        } else {
            // https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#rfc.section.3.1
            request.headers().set(HttpHeaderNames.AUTHORIZATION, signature.toString());
        }
    }
}
