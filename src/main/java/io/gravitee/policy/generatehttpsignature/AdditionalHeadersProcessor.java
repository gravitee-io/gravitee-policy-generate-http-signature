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

import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.gravitee.policy.generatehttpsignature.configuration.SchemeTypeConfiguration;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class AdditionalHeadersProcessor {

    private final List<String> headerNames;
    private final String delimiter;

    public AdditionalHeadersProcessor(GenerateHttpSignaturePolicyConfiguration configuration) {
        this.headerNames = List.copyOf(Optional.ofNullable(configuration.headers()).orElseGet(List::of));
        this.delimiter = configuration.headersDelimiter();
    }

    public String processHeaders(String payload, Function<String, String> headerGetter) {
        validateHeaders();

        StringBuilder result = new StringBuilder(payload.length() + 64);

        for (String headerName : headerNames) {
            String headerValue = headerGetter.apply(headerName);

            if (headerValue == null) {
                throw new IllegalArgumentException("Required header '" + headerName + "' is missing");
            }

            result.append(headerValue).append(delimiter);
        }

        result.append(payload);

        log.debug("Payload prepared with additional headers (headersCount={}, finalLength={})", headerNames.size(), result.length());

        return result.toString();
    }

    private void validateHeaders() {
        if (headerNames.isEmpty()) {
            throw new IllegalArgumentException("Additional headers enabled, but no headers configured");
        }
    }
}
