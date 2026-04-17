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

import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.http.HttpHeaderNames;
import io.gravitee.gateway.api.http.HttpHeaders;
import io.gravitee.gateway.reactive.api.ExecutionFailure;
import io.gravitee.gateway.reactive.api.context.http.HttpBaseExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpMessageExecutionContext;
import io.gravitee.gateway.reactive.api.context.http.HttpPlainExecutionContext;
import io.gravitee.gateway.reactive.api.message.Message;
import io.gravitee.gateway.reactive.api.policy.http.HttpPolicy;
import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.gravitee.policy.generatehttpsignature.configuration.HttpSignatureScheme;
import io.gravitee.policy.generatehttpsignature.v3.GenerateHttpSignaturePolicyV3;
import io.reactivex.rxjava3.core.Completable;
import io.reactivex.rxjava3.core.Maybe;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tomitribe.auth.signatures.Signature;
import org.tomitribe.auth.signatures.Signer;

/**
 * @author Brent HUNTER (brent.hunter at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GenerateHttpSignaturePolicy extends GenerateHttpSignaturePolicyV3 implements HttpPolicy {

    private static final Logger logger = LoggerFactory.getLogger(GenerateHttpSignaturePolicy.class);

    private final AdditionalHeadersProcessor headersProcessor;

    public GenerateHttpSignaturePolicy(GenerateHttpSignaturePolicyConfiguration configuration) {
        super(configuration);
        this.headersProcessor = new AdditionalHeadersProcessor(configuration);
    }

    @Override
    public String id() {
        return "generate-http-signature";
    }

    // ==========================
    // HTTP REQUEST
    // ==========================
    @Override
    public Completable onRequest(HttpPlainExecutionContext ctx) {
        List<String> configuredHeaders = new ArrayList<>(Optional.ofNullable(configuration.headers()).orElseGet(List::of));

        if (configuration.signHeaders()) {
            final String checkHeadersErrorMessage = checkHeaders(ctx.request().headers(), configuredHeaders);
            if (checkHeadersErrorMessage != null) {
                logger.warn(checkHeadersErrorMessage);
                return interrupt(
                    ctx,
                    new ExecutionFailure(400).key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION).message(checkHeadersErrorMessage)
                );
            }
        }

        if (configuration.signPayload()) {
            return ctx
                .request()
                .body()
                .flatMapCompletable(body -> handleRequestKeyIdResolution(ctx, configuredHeaders, body.toString()))
                .onErrorResumeNext(th -> {
                    logger.error("Http signature generation failed (HTTP request)", th);
                    return interrupt(
                        ctx,
                        new ExecutionFailure(500).key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION).message("Webhook signature generation failed")
                    );
                });
        }

        return handleRequestKeyIdResolution(ctx, configuredHeaders, "")
            .onErrorResumeNext(th -> {
                logger.error("Signature generation failed (HTTP request)", th);
                return interrupt(
                    ctx,
                    new ExecutionFailure(500).key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION).message("Signature generation failed")
                );
            });
    }

    // ==========================
    // HTTP RESPONSE
    // ==========================
    @Override
    public Completable onResponse(HttpPlainExecutionContext ctx) {
        List<String> configuredHeaders = new ArrayList<>(Optional.ofNullable(configuration.headers()).orElseGet(List::of));

        if (configuration.signHeaders()) {
            final String checkHeadersErrorMessage = checkHeaders(ctx.response().headers(), configuredHeaders);
            if (checkHeadersErrorMessage != null) {
                logger.warn(checkHeadersErrorMessage);
                return interrupt(
                    ctx,
                    new ExecutionFailure(500).key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION).message(checkHeadersErrorMessage)
                );
            }
        }

        return ctx
            .response()
            .body()
            .flatMapCompletable(buffer ->
                handleResponseKeyIDResolution(
                    ctx,
                    configuredHeaders,
                    buffer.toString(),
                    ctx.response().headers()::get,
                    ctx.response().headers(),
                    GenerateHttpSignaturePolicy::interrupt
                )
            )
            .onErrorResumeNext(th -> {
                logger.error("Http signature generation failed (HTTP response)", th);
                return interrupt(
                    ctx,
                    new ExecutionFailure(500).key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION).message("Webhook signature generation failed")
                );
            });
    }

    // ==========================
    // HTTP MESSAGE RESPONSE
    // ==========================
    @Override
    public Completable onMessageResponse(HttpMessageExecutionContext ctx) {
        return ctx.response().onMessage(message -> handleMessageKeyIdResolution(ctx, message));
    }

    private Maybe<Message> handleMessageKeyIdResolution(HttpMessageExecutionContext ctx, Message message) {
        List<String> configuredHeaders = new ArrayList<>(Optional.ofNullable(configuration.headers()).orElseGet(List::of));

        if (configuration.signHeaders()) {
            final String checkHeadersErrorMessage = checkHeaders(message.headers(), configuredHeaders);
            if (checkHeadersErrorMessage != null) {
                logger.error("Signature generation failed (Message response)");
                new ExecutionFailure(500).key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION).message(checkHeadersErrorMessage);
            }
        }
        return resolveKeyId(TemplateEngine.templateEngine())
            .flatMapCompletable(keyId -> handleMessageSignature(ctx, configuredHeaders, keyId, message))
            .andThen(Maybe.just(message));
    }

    private Completable handleRequestKeyIdResolution(HttpPlainExecutionContext ctx, List<String> configuredHeaders, String payload) {
        return resolveKeyId(TemplateEngine.templateEngine())
            .flatMapCompletable(keyId ->
                handleSignatureGeneration(
                    ctx,
                    configuredHeaders,
                    keyId,
                    payload,
                    ctx.request().timestamp(),
                    ctx.request().headers()::get,
                    ctx.request().headers(),
                    GenerateHttpSignaturePolicy::interrupt
                )
            );
    }

    private <T extends HttpBaseExecutionContext> Completable handleMessageSignature(
        HttpMessageExecutionContext ctx,
        List<String> configuredHeaders,
        String keyId,
        Message message
    ) {
        return handleSignatureGeneration(
            ctx,
            configuredHeaders,
            keyId,
            message.content().toString(),
            message.timestamp(),
            message.headers()::get,
            message.headers(),
            (c, failure) -> c.interruptMessageWith(failure).ignoreElement()
        );
    }

    private <T extends HttpBaseExecutionContext> Completable handleResponseKeyIDResolution(
        T ctx,
        List<String> configuredHeaders,
        String payload,
        Function<String, String> headerGetter,
        HttpHeaders targetHeaders,
        BiFunction<T, ExecutionFailure, Completable> interrupt
    ) {
        return resolveKeyId(TemplateEngine.templateEngine())
            .flatMapCompletable(keyId ->
                handleSignatureGeneration(
                    ctx,
                    configuredHeaders,
                    keyId,
                    payload,
                    ctx.request().timestamp(),
                    headerGetter,
                    targetHeaders,
                    interrupt
                )
            );
    }

    private <T extends HttpBaseExecutionContext> Completable handleSignatureGeneration(
        T ctx,
        List<String> configuredHeaders,
        String keyId,
        String payload,
        Long timestamp,
        Function<String, String> headerGetter,
        HttpHeaders headers,
        BiFunction<T, ExecutionFailure, Completable> interrupt
    ) {
        return resolveSecret(ctx.getTemplateEngine())
            .flatMapCompletable(secret -> {
                String processedPayload;
                try {
                    processedPayload = processAdditionalHeaders(payload, headerGetter);
                } catch (IllegalArgumentException e) {
                    logger.warn("Invalid additional headers configuration: {}", e.getMessage());
                    return interrupt.apply(
                        ctx,
                        new ExecutionFailure(500).key(HTTP_SIGNATURE_ADDITIONAL_HEADERS_NOT_VALID).message(e.getMessage())
                    );
                }
                generateAndSetSignature(
                    configuredHeaders,
                    keyId,
                    secret,
                    processedPayload,
                    headers,
                    timestamp,
                    configuration.signMethod() ? ctx.request().method().name().toLowerCase() : "",
                    configuration.signUri() ? ctx.request().uri() : "",
                    configuration.signHeaders()
                );

                return Completable.complete();
            })
            .onErrorResumeNext(err -> {
                logger.error("Http signature generation failed", err);
                return interrupt.apply(
                    ctx,
                    new ExecutionFailure(500)
                        .key(HTTP_SIGNATURE_IMPOSSIBLE_GENERATION)
                        .message(err.getMessage() != null ? err.getMessage() : "Http signature generation failed")
                );
            });
    }

    private void generateAndSetSignature(
        List<String> configuredHeaders,
        String keyId,
        String secret,
        String payload,
        HttpHeaders headers,
        Long timestamp,
        String method,
        String uri,
        boolean signHeaders
    ) throws IOException {
        if (configuration.created()) {
            configuredHeaders.add("(created)");
        }
        if (configuration.expires()) {
            configuredHeaders.add("(expires)");
        }
        Signature signatureFromConfiguration = super.buildSignatureFromConfiguration(
            () -> keyId,
            configuredHeaders,
            () -> timestamp,
            signHeaders
        );
        Signer signer = super.buildSigner(signatureFromConfiguration, () -> secret);
        logger.debug("Method and URI: {} {}", method, uri);
        Signature signature = signer.sign(method, uri, headers.toSingleValueMap(), payload);
        setSignatureHeader(headers, configuration.targetSignatureHeader(), signature);
    }

    private <T extends HttpBaseExecutionContext> void setSignatureHeader(
        HttpHeaders headers,
        String targetSignatureHeader,
        Signature signature
    ) {
        if (HttpSignatureScheme.SIGNATURE.equals(configuration.scheme())) {
            final String substring = signature.toString().substring(10); // Remove the "Signature " part of the signature
            headers.set("Signature", substring);
        } else if (HttpSignatureScheme.AUTHORIZATION.equals(configuration.scheme())) {
            headers.set(HttpHeaderNames.AUTHORIZATION, signature.toString());
        } else {
            headers.set(targetSignatureHeader, signature.toString().substring(10));
        }
    }

    // ==========================
    // HELPERS
    // ==========================
    private Maybe<String> resolveSecret(TemplateEngine templateEngine) {
        return templateEngine
            .eval(configuration.secret(), String.class)
            .switchIfEmpty(Maybe.error(new IllegalStateException("Secret could not be resolved")));
    }

    private Maybe<String> resolveKeyId(TemplateEngine templateEngine) {
        return templateEngine
            .eval(configuration.keyId(), String.class)
            .switchIfEmpty(Maybe.error(new IllegalStateException("KeyId could not be resolved")));
    }

    private String processAdditionalHeaders(String payload, Function<String, String> headerGetter) {
        if (!configuration.prependHeadersToBody()) {
            return payload;
        }
        return headersProcessor.processHeaders(payload, headerGetter);
    }

    private static Completable interrupt(HttpPlainExecutionContext ctx, ExecutionFailure executionFailure) {
        return ctx.interruptWith(executionFailure);
    }
}
