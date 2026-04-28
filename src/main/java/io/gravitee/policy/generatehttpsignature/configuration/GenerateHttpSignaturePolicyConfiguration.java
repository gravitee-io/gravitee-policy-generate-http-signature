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
package io.gravitee.policy.generatehttpsignature.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import java.util.ArrayList;
import java.util.List;
import lombok.Builder;

/**
 * @author Yann TAVERNIER (yann.tavernier at graviteesource.com)
 * @author GraviteeSource Team
 */
@Builder
public record GenerateHttpSignaturePolicyConfiguration(
    String keyId,
    HttpSignatureScheme scheme,
    Algorithm algorithm,
    String secret,
    // List of headers which the client should at least use for signature creation
    List<String> headers,
    // Optional - Headers delimiter for additional headers to add to the signature creation
    String headersDelimiter,
    boolean created,
    boolean expires,
    long validityDuration,
    // Optional - custom header name for the signature, only used if scheme is CUSTOM_HEADER
    String targetSignatureHeader,
    boolean signHeaders,
    boolean signPayload,
    boolean prependHeadersToBody,
    boolean signMethod,
    boolean signUri
) implements PolicyConfiguration {}
