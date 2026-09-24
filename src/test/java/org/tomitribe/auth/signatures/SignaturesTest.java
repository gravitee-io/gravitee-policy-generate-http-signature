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
package org.tomitribe.auth.signatures;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SignaturesTest {

    private static final long CREATED_MS = 1758400000000L;
    private static final String CREATED_SECONDS = "1758400000";
    private static final List<String> REQUIRED = List.of("x-api-key", "(created)");
    private static final Map<String, String> HEADERS = Map.of("X-Api-Key", "abcd");
    private static final String CANONICAL = "x-api-key: abcd\n(created): " + CREATED_SECONDS;

    @Test
    void shouldNotPrependAnythingWhenThereIsNoPayload() {
        String signingString = Signatures.createSigningString(REQUIRED, "get", "/api", HEADERS, CREATED_MS, null);

        assertThat(signingString).isEqualTo(CANONICAL);
    }

    @Test
    void shouldPrependAnEmptyLineWhenThePayloadIsAnEmptyOne() {
        String signingString = Signatures.createSigningStringWithPayload(REQUIRED, "get", "/api", HEADERS, CREATED_MS, null, "");

        assertThat(signingString).isEqualTo("\n" + CANONICAL);
    }

    @Test
    void shouldPrependThePayloadWhenThereIsOne() {
        String signingString = Signatures.createSigningStringWithPayload(
            REQUIRED,
            "get",
            "/api",
            HEADERS,
            CREATED_MS,
            null,
            "{\"hello\":\"world\"}"
        );

        assertThat(signingString).isEqualTo("{\"hello\":\"world\"}\n" + CANONICAL);
    }
}
