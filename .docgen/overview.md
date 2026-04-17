# HTTP Signature Generator Policy

[![Available at Gravitee.io](https://img.shields.io/static/v1?label=Available%20at&message=Gravitee.io&color=1EC9D2)](https://download.gravitee.io/#graviteeio-apim/plugins/policies/gravitee-policy-generate-http-signature/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/gravitee-io/gravitee-policy-generate-http-signature/blob/master/LICENSE.txt)
[![Releases](https://img.shields.io/badge/semantic--release-conventional%20commits-e10079?logo=semantic-release)](https://github.com/gravitee-io/gravitee-policy-generate-http-signature/releases)
[![CircleCI](https://circleci.com/gh/gravitee-io/gravitee-policy-generate-http-signature.svg?style=svg)](https://circleci.com/gh/gravitee-io/gravitee-policy-generate-http-signature)

## Phase

| onRequest | onResponse | onMessageRequest | onMessageResponse |
|:---------:|:----------:|:----------------:|:-----------------:|
|     X     |     X      |        -         |         X         |

## Description

Generates a HMAC signature against the outbound HTTP request headers, body or Message, and optionally additional custom header(s), to ensure its identity. Typically used (in a Gravitee V4-Message API with Protocol Mediation) to generate & attach a HMAC signature to request headers, response body or an outbound message to a remote Webhook.

HMAC Signatures are a kind of authentication method which is adding a level of security. It ensures the request has originated from the known source and has not been tampered with.

The sender of the message generates a HMAC signature (typically stored in a header of the request) and is then validated by the receiver using a pre-shared secret. This policy will generate that signature, and add it into a HTTP header in the outbound request headers, response body or message.

The "Signature" is based on the model that the receiver must authenticate itself with a digital signature produced by a shared symmetric key (e.g.: HMAC). Also known as the shared "secret".

> When combining this policy with the AVRO or Protobuf (binary to text) transformation policies, remember to order that policy beforehand (so this policy receives the message as plain text in order to generate the HMAC signature).

## Configuration

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

### Http Signature Generator Policy Request flow example:

```json
{
    "policy": "generate-http-signature",
    "configuration": {
        "scheme":"AUTHORIZATION",
        "validityDuration":30,
        "keyId":"my-key-id",
        "secret":"my-passphrase",
        "algorithm":"HMAC_SHA256",
        "headers":["X-Gravitee-Header","Host"],
        "signHeaders": true,
        "signMethod": true,
        "signURI": true,
        "created": true,
        "expires": true
    }
}
```

### Http Signature Generator Policy Message Subscribe flow example:

```json
{
  "policy": "generate-http-signature",
  "configuration": {
    "scheme":"CUSTOM_HEADER",
    "keyId":"my-key-id",
    "secret":"my-passphrase",
    "algorithm":"HMAC_SHA256",
    "headers":["X-Gravitee-Header","Host"],
    "signHeaders": false,
    "signPayload": true,
    "prependHeadersToBody": true,
    "headersDelimiter": ".",
    "created": true,
    "expires": true
  }
}
```

## Example Usage

This example describes how to generate a HMAC signature for each outbound message delivered from an Event Broker (e.g.:Confluent) via a Webhook (PUSH Plan) - using Protocol Mediation.

For added complexity, you may want the HMAC signature to be generated from both the Message Content AND a Message Header. In our protocol mediation scenario, when publishing messages into the Event Broker you can use the `Transform Headers` policy to convert HTTP Headers into Message Headers. And then when subscribing to or consuming those messages, the HMAC Signature can be generated from both the Message Content AND a Message Header(s).

Add this policy into the Subscribe phase (of the Event Messages flow). Remember to order any other transformation policies (like AVRO<>JSON) before this policy.

Policy configuration; specify the name of the new Signature Header to add to the outbound message, as well as the secret and algorithm type. You can now add additional Message Header(s) from your Message in your Event Broker.

### Receiving of Webhook (with HMAC Signature Header applied) example:

```
Webhook.site:
  "request":{
    "method":"POST",
    "url":"https://webhook.site/5de85005-abcd-1234-2ad18ef8b07f",
    "headers":[
      {"name":"x-hmac-signature","value":"P247Tg1qbJiokTKO2hVd17B6Nb6WfaMhgdN/YB9DnO4="},
      {"name":"my-custom-header-confluent","value":"some_unique_value"},
      {"name":"x-gravitee-request-id","value":"4f60cb44-9598-4c80-a0cb-4495984c80a0"}
    ],
    "bodySize":108,
    "postData":{
      "text":"{\"my_field1\":16,\"my_field2\":\"This is a message from HTTP POST to Confluent Cloud (using a Schema Registry)\"}"}},
      ...
```

Now the customer or receiver can validate this request by combining the `my-custom-header-confluent` header value and the HTTP body/content, and comparing HMAC signatures.

Don't forget to include the `headers delimiter` when sharing the `secret` with the receiver (so they use the exact same content to generate & validate the HMAC signature)!

### Validating the HMAC Signature of the received request (Python) example:

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

## Http Status Code

| Code | Message |
|------|---------|
| `400` | In case of: <br>• Request does not contain every header of configuration headers list<br>•Request does not contain 'Date' header and configuration headers list is empty. Policy needs at least 'Date' header to create a signature.<br>• Unable to sign because of bad configuration.|
| `500` | In case of:<br>• Missing target signature header or secret<br>• Response does not contain the specified headers to use for signature generation<br>• Signature generation failure (such as not being able to read the payload or message) |

## Errors

If you're looking to override the default response provided by the policy, you can do it thanks to the response templates feature. These templates must be define at the API level (see `Response Templates` from the `Proxy` menu).

Here are the error keys sent by this policy:

| Key | Parameters |
|-----|------------|
| HTTP_SIGNATURE_IMPOSSIBLE_GENERATION | - |
| HTTP_SIGNATURE_ADDITIONAL_HEADERS_NOT_VALID | - |

