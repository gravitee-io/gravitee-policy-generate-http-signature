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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.gravitee.policy.generatehttpsignature.configuration.Algorithm;
import io.gravitee.policy.generatehttpsignature.configuration.GenerateHttpSignaturePolicyConfiguration;
import io.gravitee.policy.generatehttpsignature.configuration.HttpSignatureScheme;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AdditionalHeadersProcessorTest {

    private GenerateHttpSignaturePolicyConfiguration configuration;

    @BeforeEach
    void setUp() {
        configuration = GenerateHttpSignaturePolicyConfiguration.builder().algorithm(Algorithm.HMAC_SHA256).build();
    }

    @Test
    void shouldThrowExceptionWhenNoHeadersConfigured() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.CUSTOM_HEADER)
                .headers(List.of())
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);

        assertThatThrownBy(() -> processor.processHeaders("payload", header -> "value"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Additional headers enabled, but no headers configured");
    }

    @Test
    void shouldProcessSingleHeaderCorrectly() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.CUSTOM_HEADER)
                .headers(List.of("X-Custom-Header"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Custom-Header", "custom-value");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo("custom-value:test-payload");
    }

    @Test
    void shouldProcessMultipleHeadersCorrectly() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(Arrays.asList("X-Header-1", "X-Header-2", "X-Header-3"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Header-1", "value1");
        headers.put("X-Header-2", "value2");
        headers.put("X-Header-3", "value3");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo("value1:value2:value3:test-payload");
    }

    @Test
    void shouldThrowExceptionWhenRequiredHeaderIsMissing() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(List.of("X-Required-Header"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);

        assertThatThrownBy(() -> processor.processHeaders("test-payload", headers::get))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Required header 'X-Required-Header' is missing");
    }

    @Test
    void shouldThrowExceptionWhenOneOfMultipleHeadersIsMissing() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.CUSTOM_HEADER)
                .headers(Arrays.asList("X-Header-1", "X-Header-2", "X-Header-3"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Header-1", "value1");
        headers.put("X-Header-3", "value3");
        // X-Header-2 is missing

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);

        assertThatThrownBy(() -> processor.processHeaders("test-payload", headers::get))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Required header 'X-Header-2' is missing");
    }

    @Test
    void shouldHandleEmptyPayload() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(List.of("X-Custom-Header"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Custom-Header", "custom-value");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("", headers::get);

        assertThat(result).isEqualTo("custom-value:");
    }

    @Test
    void shouldHandleEmptyHeaderValue() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(List.of("X-Custom-Header"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Custom-Header", "");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo(":test-payload");
    }

    @Test
    void shouldHandleDifferentDelimiters() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(Arrays.asList("X-Header-1", "X-Header-2"))
                .headersDelimiter("|")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Header-1", "value1");
        headers.put("X-Header-2", "value2");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo("value1|value2|test-payload");
    }

    @Test
    void shouldHandleEmptyDelimiter() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(Arrays.asList("X-Header-1", "X-Header-2"))
                .headersDelimiter("")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Header-1", "value1");
        headers.put("X-Header-2", "value2");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo("value1value2test-payload");
    }

    @Test
    void shouldHandleSpecialCharactersInHeaderValues() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(List.of("X-Custom-Header"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Custom-Header", "value-with-special-chars!@#$%^&*()");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo("value-with-special-chars!@#$%^&*():test-payload");
    }

    @Test
    void shouldHandleUnicodeInHeaderValues() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.SIGNATURE)
                .headers(List.of("X-Custom-Header"))
                .headersDelimiter(":")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("X-Custom-Header", "Hello 世界 🌍");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("test-payload", headers::get);

        assertThat(result).isEqualTo("Hello 世界 🌍:test-payload");
    }

    @Test
    void shouldMaintainHeaderOrder() {
        configuration =
            GenerateHttpSignaturePolicyConfiguration
                .builder()
                .algorithm(Algorithm.HMAC_SHA256)
                .scheme(HttpSignatureScheme.CUSTOM_HEADER)
                .headers(Arrays.asList("Header-A", "Header-B", "Header-C"))
                .headersDelimiter("-")
                .prependHeadersToBody(true)
                .build();

        Map<String, String> headers = new HashMap<>();
        headers.put("Header-A", "A");
        headers.put("Header-B", "B");
        headers.put("Header-C", "C");

        AdditionalHeadersProcessor processor = new AdditionalHeadersProcessor(configuration);
        String result = processor.processHeaders("payload", headers::get);

        // Verify the order matches the configuration order, not the map order
        assertThat(result).isEqualTo("A-B-C-payload");
    }
}
