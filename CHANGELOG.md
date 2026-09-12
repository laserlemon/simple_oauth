## [1.0.0] - 2026-09-12

### Changed

* Every file declares `frozen_string_literal: true`, and the explicit `freeze` calls on string literals it makes redundant are gone
* Drop the `base64` runtime dependency: `pack("m0")` and `unpack1("m")` encode and decode Base64 in core Ruby, so the gem now has no runtime dependencies at all
* Drop the `cgi` runtime dependency: query strings and form bodies are read with `URI.decode_www_form`, which Ruby ships in every supported version
* **Breaking**: raise `ParseError` when an Authorization header, form body, or query string repeats an OAuth protocol parameter, which RFC 5849 Section 3.2 does not allow; `Header.parse` previously kept the last value and `Header.parse_form_body` the first, so the two disagreed about which one a request carried
* **Breaking**: rename `Signature.methods` to `Signature.registered_methods`, so that `Signature.methods` is the module's own method list again
* **Breaking**: define `VERSION` in `SimpleOAuth`, the module the rest of the library uses, rather than in a second `SimpleOauth` module; `SimpleOauth::VERSION` is gone and `SimpleOAuth::VERSION` now resolves
* **Breaking**: `Signature.rsa?` raises `ArgumentError` for a signature method that is not registered, as `Signature.digest`, `sign`, and `verify` already do, rather than answering false
* `SimpleOAuth::Error` is the base of every error the library raises, so `rescue SimpleOAuth::Error` catches `ParseError`, `InvalidOptionsError`, and `OAuth2::Error` alike

### Fixed

* Treat only `&` as a parameter separator when reading a query string or form body; a `;` is part of the value, as every current server reads it, so `?a=1;b=2` no longer signs two parameters where the server sees one

### Added

* OAuth 2.0 request builders and response parsers in `SimpleOAuth::OAuth2`, which make no HTTP requests:
  * `Client#authorization_url` for the authorization code flow, which names `pkce` so that a client either sends a challenge or says `pkce: nil`, as OAuth 2.1 asks every client for one; a `state` is optional alongside a challenge, and required without one
  * `Client#authorization_code_request`, `#refresh_token_request`, and `#client_credentials_request` for the token endpoint
  * `Client#revocation_request` for the revocation endpoint (RFC 7009)
  * `client_secret_basic` and `client_secret_post` authentication for confidential clients, and public clients without a secret
  * `PKCE` verifiers with `S256` and `plain` challenges (RFC 7636)
  * `AuthorizationResponse.parse`, which reads the response an authorization server returns to the redirect URI: it raises the error the server reported, a `state` that is not the one the request sent, an `iss` that is not the expected issuer (RFC 9207), a repeated parameter, or a response with no code
  * A `params` option on every request builder, for what an extension adds to a request, such as the resource indicator of RFC 8707
  * `Token.from_response` and `Error.from_response` for token and error responses, rejecting a response whose access token is missing, null, or empty, or whose lifetime is not a number of seconds

## [0.5.1] - 2026-09-12

### Fixed

* Build the signature base string with a String conversion that every supported Ruby offers; `Header#url` called `URI::Generic#to_str`, which arrived in `uri` 0.13, so it raised `NoMethodError` on a stock Ruby 3.2, the oldest version the gem claims to support
* Sign a parameter that carries no value, such as a bare `?flag` in the query string or the `c2` of the RFC 5849 Section 3.4.1.3.1 example, as `name=` rather than dropping it from the signature base string; a request carrying one signed differently than the server computes, so it was rejected

## [0.5.0] - 2026-09-12

### Added

* `Header.from_request`, which builds a header for a request object such as a `Net::HTTPRequest`, signing its query parameters, its form-encoded body, or hashing any other body
* `Header.parse_query`, for OAuth credentials sent in a query string
* `Signature.digest`, and a `digest:` option on `Signature.register`, which gives the hash algorithm a signature method signs with
* `Signature.verify` and a `verify:` option on `Signature.register`, for signature methods that cannot be verified by recomputing the signature
* `Signature.decode_base64`

### Fixed

* Check `oauth_body_hash` against the body a header was built with when verifying, so a body changed after signing no longer verifies against the hash its signature covers
* Verify signatures without merging the given secrets into the header's own options, where anything else reading the header could see them
* Compare signatures in constant time when verifying
* Compute `oauth_body_hash` with the hash algorithm of the signature method, such as SHA-256 for HMAC-SHA256; it was always SHA-1
* Sign a parameter whose value is an Array as one parameter per value, as a repeated parameter; the Array was previously signed as its Ruby representation
* Verify RSA signatures with the signer's public key, which is all a verifier has; `Header#valid?` previously recomputed the signature and so needed the private key
* Match the form-encoded media type exactly when signing a body, rather than by prefix, so a media type such as `application/x-www-form-urlencoded-json` is hashed instead of signed as parameters, and `Application/X-WWW-Form-Urlencoded` is recognized

## [0.4.2] - 2026-09-12

### Added

* Document passing `Header` parameters as an Array of key-value pairs when a key repeats

### Fixed

* Accept an Array of key-value pairs as `Header` parameters in the RBS signatures, which already worked at runtime

## [0.4.1] - 2026-04-20

### Fixed

* Remove `URI::RFC2396_PARSER` stub from RBS signatures to avoid duplicate declaration error with RBS 4.0.2, which now ships the constant in its stdlib `uri` signatures

## [0.4.0] - 2026-02-01

### Added

* Extensible signature method registry allowing custom signature methods to be registered at runtime
* Support for RSA-SHA256 and HMAC-SHA256 signature methods
* OAuth Request Body Hash support (`oauth_body_hash` parameter) for signing requests with non-form-encoded bodies
* Support for parsing OAuth credentials from POST body via `Header.parse_form_body`
* Support for `realm` parameter in OAuth Authorization header

### Fixed

* Avoid symbolizing untrusted input in parse methods for security
* Refactored `Header.parse` for improved robustness using StringScanner

### Changed

* **Breaking**: `Signature.rsa?` raises `ArgumentError` for a signature method that is not registered, as `Signature.digest`, `sign`, and `verify` already do, rather than answering false
* `SimpleOAuth::Error` is the base of every error the library raises, so `rescue SimpleOAuth::Error` catches `ParseError`, `InvalidOptionsError`, and `OAuth2::Error` alike

* Supports Ruby 3.2, 3.3, 3.4, and 4.0
* Added `base64` and `cgi` as explicit runtime dependencies
* Migrated test suite from RSpec to Minitest

