The Generate HTTP Signature policy automatically generates HMAC signatures for proxied HTTP requests or outbound HTTP responses or messages. This ensures message integrity and authenticity for consumers.

## How it works

The policy generates a cryptographic signature (HMAC) of the request headers or response body and optionally includes additional headers in the signature. The signature is then added to the proxied request or outbound response as an HTTP header that recipients can use to verify the message hasn't been tampered with.

### Signature Generation Process

Request signing involves the following steps:
1. **Extract headers**: Read the HTTP request headers specified in the configuration
2. **Extract payload**: (optional) Read the HTTP request body or message content
3. **Include created/expires** (optional): Add timestamp information to the signature for replay protection
4. **Generate HMAC**: Create a signature using the configured algorithm and secret
5. **Encode**: Base64-encode the signature
6. **Add header**: Set the signature in the configured HTTP header (e.g., `Authorization`)

Response/Message signing involves the following steps:
1. **Extract headers**: (optional) Read the HTTP response headers specified in the configuration
2. **Extract payload**: Read the HTTP response body or message content
3. **Include headers** (optional): Prepend configured header values to the payload
4. **Generate HMAC**: Create a signature using the configured algorithm and secret
5. **Encode**: Base64-encode the signature
6. **Add header**: Set the signature in the configured HTTP header

---

## Configuration

### Basic Configuration

The minimal configuration requires:

```json
{
  "scheme": "CUSTOM_HEADER",
  "keyId": "my-key-id",
  "secret": "your-secret-key",
  "targetSignatureHeader": "X-HMAC-Signature",
  "algorithm": "HMAC_SHA256",
  "signPayload": true
}
```

### Configuration Properties

| Property              | Required | Description                                                                                                                         | Default          |
|-----------------------|:--------:|-------------------------------------------------------------------------------------------------------------------------------------|------------------|
| scheme                |    X     | Signature Scheme (authorization header or signature header)                                                                         | authorization    |
| headers [List]        |          | List of headers to build the signature. If no headers, the request must at least contains `Date` header.                            |                  |
| keyId                 |    X     | The key id used to generate the signature (supports EL)                                                                             |                  |
| secret                |    X     | The secret key used to generate the HMAC signature (supports EL)                                                                    |                  |
| algorithms            |    X     | Specify the HMAC algorithm (e.g.: HMAC_SHA1, HMAC_SHA256, HMAC_SHA384, or HMAC_SHA512)                                              | HMAC_SHA256      |
| targetSignatureHeader |          | Specify the HTTP header that will contain the generated HMAC signature                                                              | X-HMAC-Signature |
| signHeaders           |          | Base signing process on the request/response/message headers                                                                        | true             |
| signPayload           |          | Base signing process on the request/response/message payload (Required for response flow)                                           | false            |
| prependHeadersToBody  |          | The defined headers will be prepended to the body for signature generation. (Only applicable if the signPaylonad option is enabled) | false            |
| headersDelimiter      |          | Specify a delimiter to separate each header and the body/message                                                                    | .                |
| signMethod            |          | Base signing process on the request method name (Highly recommended for request flow)                                               | true             |
| signURI               |          | Base signing process on the request URI name (Highly recommended for request flow)                                                  | true             |
| created               |          | Include the created timestamp in the signature and (created) header                                                                 | true             |
| expieres              |          | Include the expires timestamp in the signature and (expires) header                                                                 | true             |
| validityDuration      |          | Signature's maximum validation duration in seconds (minimum is 1). Applied when `expires` is set to true                            | 3                |

---

## Examples

### Example 1: Basic Signature Generation

Generate a signature from the response body only:

```json
{
  "scheme": "CUSTOM_HEADER",
  "keyId": "my-key-id",
  "secret": "my-shared-secret-key",
  "targetSignatureHeader": "X-HMAC-Signature",
  "algorithm": "HMAC_SHA256",
  "signPayload": true
}
```

**Input (Response Body):**
```json
{"userId": 123, "event": "user.created"}
```

**Output Header:**
```
X-HMAC-Signature: kJ8Fh2xQ9mN... (base64-encoded signature)
```

---

### Example 2: Signature with Additional Headers

Include specific headers in the signature to prevent replay attacks:

```json
{
  "scheme": "CUSTOM_HEADER",
  "headersDelimiter": ":",
  "headers": ["kafka-topic", "kafka-partition"],
  "keyId": "my-key-id",
  "secret": "webhook-signing-secret",
  "targetSignatureHeader": "X-HMAC-Signature",
  "algorithm": "HMAC_SHA256",
  "signPayload": false,
  "prependHeadersToBody": true
}
```

**Input:**
- Header `X-Request-ID`: `abc123`
- Header `X-Timestamp`: `1609459200`
- Body: `{"userId": 123}`

**Signed Content:**
```
abc123:1609459200:{"userId": 123}
```

This combined string is what gets signed, ensuring both the body and critical headers are protected.

---

### Example 3: Using Secret Manager

Retrieve the secret from a secure vault:

```json
{
  "scheme": "CUSTOM_HEADER",
  "keyId": "my-key-id",
  "secret": "{#secrets.get('/dev/secret/gravitee/webhook-signing-key')}",
  "targetSignatureHeader": "X-HMAC-Signature",
  "algorithm": "HMAC_SHA256",
  "signPayload": true
}
```

The EL expression `{#secrets.get(...)}` dynamically retrieves the secret from your configured secret manager at runtime.

---

### Example 4: Message API (Kafka, MQTT)

For V4 Message APIs, include message headers in the signature:

```json
{
  "scheme": "CUSTOM_HEADER",
  "headersDelimiter": ":",
  "headers": [
      "kafka-topic",
      "kafka-partition"
    ],
  "keyId": "my-key-id",
  "secret": "webhook-signing-secret",
  "targetSignatureHeader": "X-HMAC-Signature",
  "algorithm": "HMAC_SHA256",
  "signPayload": true,
  "prependHeadersToBody": true
}
```

This ensures the signature covers both message metadata and content.

---

## Algorithm Selection

Choose the appropriate HMAC algorithm based on your security requirements:

| Algorithm     | Output Size | Security Level | Use Case |
|---------------|-------------|----------------|----------|
| `HMAC_SHA1`   | 160 bits | ⚠️ Legacy | Only for backward compatibility |
| `HMAC_SHA256` | 256 bits | ✅ Standard | Recommended for most use cases |
| `HMAC_SHA384` | 384 bits | ✅ High | Enhanced security requirements |
| `HNAC_SHA512` | 512 bits | ✅ Very High | Maximum security, larger signatures |

> **Recommendation**: Use `HmacSHA256` or higher. Avoid `HmacSHA1` for new implementations.

---

## Validating Signatures

Recipients of the webhook must validate the signature to ensure message integrity. Here are examples in different languages:

### Python

```python
#!/usr/bin/env python3
"""
HTTP Signature verification script compatible with Gravitee's GenerateHttpSignaturePolicy.
Replicates the signature generation logic to verify signatures match.
"""

import base64
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class HttpSignatureGenerator:
    """
    Replicates the signature generation from GenerateHttpSignaturePolicy.
    Based on org.tomitribe.auth.signatures.Signer logic.
    """
    
    def __init__(
        self,
        key_id: str,
        secret: str,
        algorithm: str = "hmac-sha256",
        headers: Optional[List[str]] = None,
        include_created: bool = False,
        include_expires: bool = False,
        validity_duration: int = 0,
        sign_method: bool = True,
        sign_uri: bool = True,
        prepend_headers_to_body: bool = False,
        headers_delimiter: str = "\n",
        scheme: str = "Authorization"
    ):
        self.key_id = key_id
        self.secret_bytes = secret.encode('utf-8')
        self.algorithm = algorithm
        self.headers = headers or []
        self.include_created = include_created
        self.include_expires = include_expires
        self.validity_duration = validity_duration
        self.sign_method = sign_method
        self.sign_uri = sign_uri
        self.prepend_headers_to_body = prepend_headers_to_body
        self.headers_delimiter = headers_delimiter
        self.scheme = scheme
        
        # Map algorithm to hash name and constructor
        self.alg_map = {
            "hmac-sha256": ("HmacSHA256", hashlib.sha256),
            "hmac-sha1": ("HmacSHA1", hashlib.sha1),
            "hmac-sha512": ("HmacSHA512", hashlib.sha512),
        }
        
        if algorithm not in self.alg_map:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def _canonicalize_header_name(self, name: str) -> str:
        """Lowercase header name as per spec."""
        return name.lower()
    
    def generate_signing_string(
        self,
        method: str,
        uri: str,
        headers: Dict[str, str],
        payload: Optional[str] = None,
        created: Optional[int] = None,
        expires: Optional[int] = None
    ) -> bytes:
        """
        Build the canonical signing string as bytes.
        """
        lines = []
        
        # 1. (request-target) if method/uri provided
        if method and uri:
            lines.append(f"(request-target): {method} {uri}")
        
        # 2. Headers block from configured headers + pseudo-headers
        header_names = list(self.headers)
        if self.include_created:
            header_names.append("(created)")
        if self.include_expires:
            header_names.append("(expires)")
        
        # Normalize headers dict to lower-case keys
        normalized_headers = {k.lower(): v for k, v in headers.items()}
        
        for name in header_names:
            if name == "(created)":
                if created is None:
                    raise ValueError("(created) requested but no timestamp provided")
                lines.append(f"(created): {created}")
            elif name == "(expires)":
                if expires is None:
                    raise ValueError("(expires) requested but no timestamp provided")
                lines.append(f"(expires): {expires}")
            else:
                canonical_name = self._canonicalize_header_name(name)
                value = normalized_headers.get(canonical_name)
                if value is None:
                    raise ValueError(f"Required header '{name}' is missing")
                lines.append(f"{canonical_name}: {value}")
        
        # Join with newline
        signing_str = "\n".join(lines)
        
        # 3. Append payload if provided
        if payload is not None:
            signing_str += "\n" + payload
        
        return signing_str.encode('utf-8')
    
    def sign(
        self,
        method: str,
        uri: str,
        headers: Dict[str, str],
        payload: Optional[str] = None,
        created: Optional[int] = None,
        expires: Optional[int] = None
    ) -> str:
        """
        Generate the signature string.
        Returns the Base64-encoded signature, without the "Signature " prefix.
        """
        # Determine created/expires if needed
        if self.include_created and created is None:
            created = int(datetime.utcnow().timestamp() * 1000)
        if self.include_expires and expires is None:
            expires = created + (self.validity_duration * 1000)
        
        # Build the signing string
        signing_bytes = self.generate_signing_string(method, uri, headers, payload, created, expires)
        
        # Compute HMAC
        _, hash_alg = self.alg_map[self.algorithm]
        # Create HMAC signer
        signature_bytes = hmac.new(self.secret_bytes, signing_bytes, hash_alg).digest()
        
        # Base64 encode
        signature_b64 = base64.b64encode(signature_bytes).decode('utf-8')
        
        return signature_b64
    
    def format_signature_header(self, signature: str) -> str:
        """
        Format the signature according to the scheme.
        Returns the full header value as it should appear in the HTTP header.
        """
        if self.scheme.lower() == "signature":
            return signature
        else:  # Authorization
            return f"Signature {signature}"


def verify_signature(
    received_signature: str,
    key_id: str,
    secret: str,
    method: str,
    uri: str,
    headers: Dict[str, str],
    payload: Optional[str] = None,
    algorithm: str = "hmac-sha256",
    headers_list: Optional[List[str]] = None,
    include_created: bool = False,
    include_expires: bool = False,
    validity_duration: int = 0,
    sign_method: bool = True,
    sign_uri: bool = True,
    prepend_headers_to_body: bool = False,
    headers_delimiter: str = "\n",
    scheme: str = "Authorization"
) -> Tuple[bool, str, str]:
    """
    Verify a signature against the given parameters.
    Returns (is_valid, generated_signature, formatted_header)
    """
    # Normalize headers to lower-case keys for canonical matching
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    # If prepend_headers_to_body is true, augment the payload with configured headers
    processed_payload = payload
    if prepend_headers_to_body and headers_list:
        parts = []
        for h in headers_list:
            h_lower = h.lower()
            if h_lower not in normalized_headers:
                raise ValueError(f"Required header '{h}' missing for prepend")
            parts.append(normalized_headers[h_lower])
        parts.append(payload or "")
        processed_payload = headers_delimiter.join(parts)
    
    # Build signature generator
    gen = HttpSignatureGenerator(
        key_id=key_id,
        secret=secret,
        algorithm=algorithm,
        headers=headers_list,
        include_created=include_created,
        include_expires=include_expires,
        validity_duration=validity_duration,
        sign_method=sign_method,
        sign_uri=sign_uri,
        prepend_headers_to_body=prepend_headers_to_body,
        headers_delimiter=headers_delimiter,
        scheme=scheme
    )
    
    # Determine method/uri to sign based on flags
    actual_method = method.lower() if sign_method else ""
    actual_uri = uri if sign_uri else ""
    
    # Compute timestamps if needed
    now_ms = int(datetime.utcnow().timestamp() * 1000)
    created_ts = now_ms if include_created else None
    if include_expires:
        expires_ts = now_ms + validity_duration * 1000
    else:
        expires_ts = None
    
    # Generate signature
    generated = gen.sign(
        method=actual_method,
        uri=actual_uri,
        headers=normalized_headers,
        payload=processed_payload,
        created=created_ts,
        expires=expires_ts
    )
    
    # Format according to scheme
    formatted = gen.format_signature_header(generated)
    
    # Clean received signature
    received_clean = received_signature.strip()
    if received_clean.lower().startswith("signature "):
        received_clean = received_clean[10:].strip()
    
    is_valid = generated == received_clean
    
    return is_valid, generated, formatted


if __name__ == "__main__":
    # Example configuration - replace with actual values
    config = {
        "key_id": "your-key-id",
        "secret": "your-secret",
        "algorithm": "hmac-sha256",
        "headers": ["date", "digest"],  # adjust to your config
        "include_created": False,
        "include_expires": False,
        "validity_duration": 300,
        "sign_method": True,
        "sign_uri": True,
        "prepend_headers_to_body": False,
        "headers_delimiter": "\n",
        "scheme": "Authorization"
    }
    
    # Example data - replace with actual response data
    response_headers = {
        "date": "Wed, 21 Oct 2015 07:28:00 GMT",
        "digest": "SHA-256=...",
    }
    payload = '{"status":"ok"}'
    received_sig = "actual-signature-from-header"
    
    valid, gen_sig, formatted = verify_signature(
        received_signature=received_sig,
        method="POST",
        uri="/webhook",
        headers=response_headers,
        payload=payload,
        **config
    )
    
    print(f"Valid: {valid}")
    print(f"Generated signature: {gen_sig}")
    print(f"Formatted header: {formatted}")
```

### Node.js

```javascript
#!/usr/bin/env node
/**
 * HTTP Signature verification script compatible with Gravitee's GenerateHttpSignaturePolicy.
 * Replicates the signature generation logic to verify signatures match.
 */

const crypto = require('crypto');

class HttpSignatureGenerator {
    /**
     * Replicates the signature generation from GenerateHttpSignaturePolicy.
     * Based on org.tomitribe.auth.signatures.Signer logic.
     */

    constructor({
                    key_id,
                    secret,
                    algorithm = "hmac-sha256",
                    headers = [],
                    include_created = false,
                    include_expires = false,
                    validity_duration = 0,
                    sign_method = true,
                    sign_uri = true,
                    prepend_headers_to_body = false,
                    headers_delimiter = "\n",
                    scheme = "Authorization"
                }) {
        this.key_id = key_id;
        this.secret = secret;
        this.algorithm = algorithm;
        this.headers = headers || [];
        this.include_created = include_created;
        this.include_expires = include_expires;
        this.validity_duration = validity_duration;
        this.sign_method = sign_method;
        this.sign_uri = sign_uri;
        this.prepend_headers_to_body = prepend_headers_to_body;
        this.headers_delimiter = headers_delimiter;
        this.scheme = scheme;

        // Map algorithm to hash name
        this.algMap = {
            "hmac-sha256": "sha256",
            "hmac-sha1": "sha1",
            "hmac-sha512": "sha512",
        };

        if (!(algorithm in this.algMap)) {
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
    }

    _canonicalizeHeaderName(name) {
        /** Lowercase header name as per spec. */
        return name.toLowerCase();
    }

    generateSigningString(
        method,
        uri,
        headers,
        payload = null,
        created = null,
        expires = null
    ) {
        /**
         * Build the canonical signing string as a Buffer.
         */
        const lines = [];

        // 1. (request-target) if method/uri provided
        if (method && uri) {
            lines.push(`(request-target): ${method} ${uri}`);
        }

        // 2. Headers block from configured headers + pseudo-headers
        const headerNames = [...this.headers];
        if (this.include_created) {
            headerNames.push("(created)");
        }
        if (this.include_expires) {
            headerNames.push("(expires)");
        }

        // Normalize headers dict to lower-case keys
        const normalizedHeaders = {};
        for (const [k, v] of Object.entries(headers)) {
            normalizedHeaders[k.toLowerCase()] = v;
        }

        for (const name of headerNames) {
            if (name === "(created)") {
                if (created === null) {
                    throw new Error("(created) requested but no timestamp provided");
                }
                lines.push(`(created): ${created}`);
            } else if (name === "(expires)") {
                if (expires === null) {
                    throw new Error("(expires) requested but no timestamp provided");
                }
                lines.push(`(expires): ${expires}`);
            } else {
                const canonicalName = this._canonicalizeHeaderName(name);
                const value = normalizedHeaders[canonicalName];
                if (value === undefined) {
                    throw new Error(`Required header '${name}' is missing`);
                }
                lines.push(`${canonicalName}: ${value}`);
            }
        }

        // Join with newline
        let signingStr = lines.join("\n");

        // 3. Append payload if provided
        if (payload !== null) {
            signingStr += "\n" + payload;
        }

        return Buffer.from(signingStr, 'utf-8');
    }

    sign(
        method,
        uri,
        headers,
        payload = null,
        created = null,
        expires = null
    ) {
        /**
         * Generate the signature string.
         * Returns the Base64-encoded signature, without the "Signature " prefix.
         */
        // Determine created/expires if needed
        if (this.include_created && created === null) {
            created = Date.now();
        }
        if (this.include_expires && expires === null) {
            expires = created + (this.validity_duration * 1000);
        }

        // Build the signing string
        const signingBytes = this.generateSigningString(method, uri, headers, payload, created, expires);

        // Compute HMAC
        const hashAlg = this.algMap[this.algorithm];
        const hmac = crypto.createHmac(hashAlg, this.secret);
        hmac.update(signingBytes);
        const signature = hmac.digest('base64');

        return signature;
    }

    formatSignatureHeader(signature) {
        /**
         * Format the signature according to the scheme.
         * Returns the full header value as it should appear in the HTTP header.
         */
        if (this.scheme.toLowerCase() === "signature") {
            return signature;
        } else {  // Authorization
            return `Signature ${signature}`;
        }
    }
}


function verifySignature(
    receivedSignature,
    key_id,
    secret,
    method,
    uri,
    headers,
    payload = null,
    algorithm = "hmac-sha256",
    headersList = null,
    include_created = false,
    include_expires = false,
    validity_duration = 0,
    sign_method = true,
    sign_uri = true,
    prepend_headers_to_body = false,
    headers_delimiter = "\n",
    scheme = "Authorization"
) {
    /**
     * Verify a signature against the given parameters.
     * Returns [is_valid, generated_signature, formatted_header]
     */
        // Normalize headers to lower-case keys for canonical matching
    const normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers)) {
        normalizedHeaders[k.toLowerCase()] = v;
    }

    // If prepend_headers_to_body is true, augment the payload with configured headers
    let processedPayload = payload;
    if (prepend_headers_to_body && headersList) {
        const parts = [];
        for (const h of headersList) {
            const hLower = h.toLowerCase();
            if (!(hLower in normalizedHeaders)) {
                throw new Error(`Required header '${h}' missing for prepend`);
            }
            parts.push(normalizedHeaders[hLower]);
        }
        parts.push(payload || "");
        processedPayload = parts.join(headers_delimiter);
    }

    // Build signature generator
    const gen = new HttpSignatureGenerator({
        key_id,
        secret,
        algorithm,
        headers: headersList,
        include_created,
        include_expires,
        validity_duration,
        sign_method,
        sign_uri,
        prepend_headers_to_body,
        headers_delimiter,
        scheme
    });

    // Determine method/uri to sign based on flags
    const actualMethod = sign_method ? method.toLowerCase() : "";
    const actualUri = sign_uri ? uri : "";

    // Compute timestamps if needed
    const nowMs = Date.now();
    const createdTs = include_created ? nowMs : null;
    const expiresTs = include_expires ? nowMs + validity_duration * 1000 : null;

    // Generate signature
    const generated = gen.sign(
        actualMethod,
        actualUri,
        normalizedHeaders,
        processedPayload,
        createdTs,
        expiresTs
    );

    // Format according to scheme
    const formatted = gen.formatSignatureHeader(generated);

    // Clean received signature
    let receivedClean = receivedSignature.trim();
    if (receivedClean.toLowerCase().startsWith("signature ")) {
        receivedClean = receivedClean.substring(10).trim();
    }

    const isValid = generated === receivedClean;

    return [isValid, generated, formatted];
}


// Example usage - replace with actual values
const config = {
    key_id: "your-key-id",
    secret: "your-secret",
    algorithm: "hmac-sha256",
    headersList: ["date", "digest"],  // adjust to your config
    include_created: false,
    include_expires: false,
    validity_duration: 300,
    sign_method: true,
    sign_uri: true,
    prepend_headers_to_body: false,
    headers_delimiter: "\n",
    scheme: "Authorization"
};

// Example data - replace with actual response data
const responseHeaders = {
    "date": "Wed, 21 Oct 2015 07:28:00 GMT",
    "digest": "SHA-256=...",
};
const payload = '{"status":"ok"}';
const receivedSig = "actual-signature-from-header";

const [valid, genSig, formatted] = verifySignature(
    receivedSig,
    config.key_id,
    config.secret,
    "POST",
    "/webhook",
    responseHeaders,
    payload,
    config.algorithm,
    config.headersList,
    config.include_created,
    config.include_expires,
    config.validity_duration,
    config.sign_method,
    config.sign_uri,
    config.prepend_headers_to_body,
    config.headers_delimiter,
    config.scheme
);

console.log(`Valid: ${valid}`);
console.log(`Generated signature: ${genSig}`);
console.log(`Formatted header: ${formatted}`);
```

### Java

```java
import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * HTTP Signature verification class compatible with Gravitee's GenerateHttpSignaturePolicy.
 * Replicates the signature generation logic to verify signatures match.
 */
public class HttpSignatureVerifier {

    public static class HttpSignatureGenerator {
        private String keyId;
        private String secret;
        private String algorithm;
        private List<String> headers;
        private boolean includeCreated;
        private boolean includeExpires;
        private int validityDuration;
        private boolean signMethod;
        private boolean signUri;
        private boolean prependHeadersToBody;
        private String headersDelimiter;
        private String scheme;

        private Map<String, String> algMap;

        public HttpSignatureGenerator(String keyId, String secret) {
            this(keyId, secret, "hmac-sha256", new ArrayList<>(), false, false, 0, true, true, false, "\n", "Authorization");
        }

        public HttpSignatureGenerator(String keyId, String secret, String algorithm, List<String> headers,
                                      boolean includeCreated, boolean includeExpires, int validityDuration,
                                      boolean signMethod, boolean signUri, boolean prependHeadersToBody,
                                      String headersDelimiter, String scheme) {
            this.keyId = keyId;
            this.secret = secret;
            this.algorithm = algorithm;
            this.headers = headers != null ? headers : new ArrayList<>();
            this.includeCreated = includeCreated;
            this.includeExpires = includeExpires;
            this.validityDuration = validityDuration;
            this.signMethod = signMethod;
            this.signUri = signUri;
            this.prependHeadersToBody = prependHeadersToBody;
            this.headersDelimiter = headersDelimiter;
            this.scheme = scheme;

            this.algMap = new HashMap<>();
            this.algMap.put("hmac-sha256", "HmacSHA256");
            this.algMap.put("hmac-sha1", "HmacSHA1");
            this.algMap.put("hmac-sha512", "HmacSHA512");

            if (!this.algMap.containsKey(algorithm)) {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }
        }

        private String canonicalizeHeaderName(String name) {
            return name.toLowerCase();
        }

        public byte[] generateSigningString(String method, String uri, Map<String, String> headers,
                                            String payload, Long created, Long expires) {
            List<String> lines = new ArrayList<>();

            // 1. (request-target) if method/uri provided
            if (method != null && !method.isEmpty() && uri != null && !uri.isEmpty()) {
                lines.add("(request-target): " + method + " " + uri);
            }

            // 2. Headers block from configured headers + pseudo-headers
            List<String> headerNames = new ArrayList<>(this.headers);
            if (this.includeCreated) {
                headerNames.add("(created)");
            }
            if (this.includeExpires) {
                headerNames.add("(expires)");
            }

            // Normalize headers dict to lower-case keys
            Map<String, String> normalizedHeaders = new HashMap<>();
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                normalizedHeaders.put(entry.getKey().toLowerCase(), entry.getValue());
            }

            for (String name : headerNames) {
                if ("(created)".equals(name)) {
                    if (created == null) {
                        throw new IllegalArgumentException("(created) requested but no timestamp provided");
                    }
                    lines.add("(created): " + created);
                } else if ("(expires)".equals(name)) {
                    if (expires == null) {
                        throw new IllegalArgumentException("(expires) requested but no timestamp provided");
                    }
                    lines.add("(expires): " + expires);
                } else {
                    String canonicalName = canonicalizeHeaderName(name);
                    String value = normalizedHeaders.get(canonicalName);
                    if (value == null) {
                        throw new IllegalArgumentException("Required header '" + name + "' is missing");
                    }
                    lines.add(canonicalName + ": " + value);
                }
            }

            // Join with newline
            String signingStr = String.join("\n", lines);

            // 3. Append payload if provided
            if (payload != null) {
                signingStr += "\n" + payload;
            }

            return signingStr.getBytes(StandardCharsets.UTF_8);
        }

        public String sign(String method, String uri, Map<String, String> headers, String payload,
                           Long created, Long expires) {
            // Determine created/expires if needed
            if (this.includeCreated && created == null) {
                created = System.currentTimeMillis();
            }
            if (this.includeExpires && expires == null) {
                expires = created + (this.validityDuration * 1000L);
            }

            // Build the signing string
            byte[] signingBytes = generateSigningString(method, uri, headers, payload, created, expires);

            // Compute HMAC
            try {
                String macAlgorithm = this.algMap.get(this.algorithm);
                Mac mac = Mac.getInstance(macAlgorithm);
                SecretKeySpec keySpec = new SecretKeySpec(this.secret.getBytes(StandardCharsets.UTF_8), macAlgorithm);
                mac.init(keySpec);
                byte[] signatureBytes = mac.doFinal(signingBytes);

                // Base64 encode
                return Base64.getEncoder().encodeToString(signatureBytes);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException("Error computing HMAC", e);
            }
        }

        public String formatSignatureHeader(String signature) {
            if ("signature".equalsIgnoreCase(this.scheme)) {
                return signature;
            } else {  // Authorization
                return "Signature " + signature;
            }
        }
    }

    public static List<Object> verifySignature(String receivedSignature, String keyId, String secret,
                                               String method, String uri, Map<String, String> headers,
                                               String payload, String algorithm, List<String> headersList,
                                               boolean includeCreated, boolean includeExpires, int validityDuration,
                                               boolean signMethod, boolean signUri, boolean prependHeadersToBody,
                                               String headersDelimiter, String scheme) {
        // Normalize headers to lower-case keys for canonical matching
        Map<String, String> normalizedHeaders = new HashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            normalizedHeaders.put(entry.getKey().toLowerCase(), entry.getValue());
        }

        // If prepend_headers_to_body is true, augment the payload with configured headers
        String processedPayload = payload;
        if (prependHeadersToBody && headersList != null) {
            List<String> parts = new ArrayList<>();
            for (String h : headersList) {
                String hLower = h.toLowerCase();
                if (!normalizedHeaders.containsKey(hLower)) {
                    throw new IllegalArgumentException("Required header '" + h + "' missing for prepend");
                }
                parts.add(normalizedHeaders.get(hLower));
            }
            parts.add(payload != null ? payload : "");
            processedPayload = String.join(headersDelimiter, parts);
        }

        // Build signature generator
        HttpSignatureGenerator gen = new HttpSignatureGenerator(
                keyId, secret, algorithm, headersList, includeCreated, includeExpires, validityDuration,
                signMethod, signUri, prependHeadersToBody, headersDelimiter, scheme
        );

        // Determine method/uri to sign based on flags
        String actualMethod = signMethod ? method.toLowerCase() : "";
        String actualUri = signUri ? uri : "";

        // Compute timestamps if needed
        long nowMs = System.currentTimeMillis();
        Long createdTs = includeCreated ? nowMs : null;
        Long expiresTs = includeExpires ? nowMs + validityDuration * 1000L : null;

        // Generate signature
        String generated = gen.sign(actualMethod, actualUri, normalizedHeaders, processedPayload, createdTs, expiresTs);

        // Format according to scheme
        String formatted = gen.formatSignatureHeader(generated);

        // Clean received signature
        String receivedClean = receivedSignature.trim();
        if (receivedClean.toLowerCase().startsWith("signature ")) {
            receivedClean = receivedClean.substring(10).trim();
        }

        boolean isValid = generated.equals(receivedClean);

        List<Object> result = new ArrayList<>();
        result.add(isValid);
        result.add(generated);
        result.add(formatted);
        return result;
    }

    public static void main(String[] args) {
        // Example configuration - replace with actual values
        Map<String, Object> config = new HashMap<>();
        config.put("key_id", "your-key-id");
        config.put("secret", "your-secret");
        config.put("algorithm", "hmac-sha256");
        config.put("headers", Arrays.asList("date", "digest"));  // adjust to your config
        config.put("include_created", false);
        config.put("include_expires", false);
        config.put("validity_duration", 300);
        config.put("sign_method", true);
        config.put("sign_uri", true);
        config.put("prepend_headers_to_body", false);
        config.put("headers_delimiter", "\n");
        config.put("scheme", "Authorization");

        // Example data - replace with actual response data
        Map<String, String> responseHeaders = new HashMap<>();
        responseHeaders.put("date", "Wed, 21 Oct 2015 07:28:00 GMT");
        responseHeaders.put("digest", "SHA-256=...");
        String payload = "{\"status\":\"ok\"}";
        String receivedSig = "actual-signature-from-header";

        List<Object> result = verifySignature(
                receivedSig,
                (String) config.get("key_id"),
                (String) config.get("secret"),
                "POST",
                "/webhook",
                responseHeaders,
                payload,
                (String) config.get("algorithm"),
                (List<String>) config.get("headers"),
                (Boolean) config.get("include_created"),
                (Boolean) config.get("include_expires"),
                (Integer) config.get("validity_duration"),
                (Boolean) config.get("sign_method"),
                (Boolean) config.get("sign_uri"),
                (Boolean) config.get("prepend_headers_to_body"),
                (String) config.get("headers_delimiter"),
                (String) config.get("scheme")
        );

        System.out.println("Valid: " + result.get(0));
        System.out.println("Generated signature: " + result.get(1));
        System.out.println("Formatted header: " + result.get(2));
    }
}
```

---

## Best Practices

### 1. Secret Management
- ✅ **DO**: Store secrets in a secure vault (use Secret Manager integration)
- ✅ **DO**: Rotate secrets regularly
- ❌ **DON'T**: Hardcode secrets in the configuration
- ❌ **DON'T**: Share secrets in plain text

### 2. Algorithm Selection
- ✅ **DO**: Use `HMAC_SHA256` or stronger
- ✅ **DO**: Document which algorithm you're using
- ❌ **DON'T**: Use `HMAC_SHA1` for new implementations

### 3. Header Selection
- ✅ **DO**: Include timestamp headers to prevent replay attacks
- ✅ **DO**: Include request ID for traceability
- ❌ **DON'T**: Include too many headers (increases complexity)

### 4. Testing
- ✅ **DO**: Test signature validation before going to production
- ✅ **DO**: Share the complete signing scheme with recipients (algorithm, delimiter, headers)
- ✅ **DO**: Verify signatures using the examples above

---

## Troubleshooting

### Signature Validation Fails

**Problem**: Recipients cannot validate the signature

**Solutions**:
1. **Verify the secret**: Ensure both sides use the exact same secret (case-sensitive)
2. **Check the algorithm**: Confirm the recipient is using the same HMAC algorithm
3. **Verify header inclusion**: If `schemeType.enabled` is true, ensure recipient includes headers in the same order
4. **Check the delimiter**: Ensure recipient uses the same delimiter character
5. **Inspect the body**: Verify the body hasn't been modified (no whitespace changes, encoding issues)

### Header Name Appears Different

**Problem**: Header appears as `X_HMAC_SIGNATURE` instead of `X-HMAC-Signature`

**Explanation**: Some web servers and CGI environments convert HTTP header names to uppercase and replace hyphens with underscores.

**Solution**: Configure your webhook receiver to check for both formats:
- `X-HMAC-Signature` (standard HTTP)
- `X_HMAC_SIGNATURE` (CGI-style)

### Empty or Missing Signature

**Problem**: The signature header is not present in the webhook

**Possible Causes**:
1. Policy is not in the response phase
2. Secret could not be resolved (check logs)
3. Policy execution failed (check for errors)

**Solution**: Check the API Gateway logs and ensure the policy is correctly configured in the response flow.

---

## Phase Compatibility

This policy executes in the following phases:

| Phase                 | HTTP Proxy API | Message API | Description                              |
|-----------------------|:--------------:|:-----------:|------------------------------------------|
| onRequest             |       ✅        |      ❌      | Generate signature for HTTP request      |
| **onResponse**        |       ✅        |      ❌      | Generate signature for HTTP responses    |
| onMessageRequest      |       ❌        |      ❌      | Not supported                            |
| **onMessageResponse** |       ❌        |      ✅      | Generate signature for message responses |

---

## Security Considerations

### What this policy provides:
- ✅ **Message integrity**: Detects if the message was tampered with
- ✅ **Authentication**: Verifies the message came from a trusted source
- ✅ **Non-repudiation**: Sender cannot deny sending the message

### What this policy does NOT provide:
- ❌ **Encryption**: Message content is not encrypted (use HTTPS/TLS)
- ❌ **Replay protection**: Without timestamps, messages can be replayed
- ❌ **Secret distribution**: You must securely share the secret with recipients

### Recommendations:
1. Always use HTTPS/TLS for transport security
2. Include timestamp headers and validate freshness on the recipient side
3. Implement secret rotation procedures
4. Monitor failed signature validations as potential security incidents
