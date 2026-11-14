## [0.5.3] - 2026-11-14

### Fixed

* Verify as fast as 0.5.1 when `Header#valid?` is not given a `signature_method`. 0.5.2 parsed the `consumer_secret` as an RSA key on every verification, which takes far longer to fail for a shared secret than verifying does, and parsed an RSA key twice. That made such a verification about 60 to 70 percent slower. Only a secret in PEM, or one that could be in DER, is now parsed, and an RSA key only once

## [0.5.2] - 2026-11-14

### Security

* `Header#valid?` no longer verifies with whatever signature method the received header claims. A server verifying RSA signatures with a client's public key, as the README showed, accepted forged requests signed with that public key as an HMAC-SHA1 or PLAINTEXT secret. Reported by Rathnadeepan (HotWater, [@HotWater-015](https://github.com/HotWater-015))
  * Given a `signature_method`, the header must claim that method
  * Without one, the header must claim an RSA method for an RSA key and an HMAC method for any other secret
  * PLAINTEXT signatures verify only when the caller names `PLAINTEXT`

### Deprecated

* Calling `Header#valid?` without a `signature_method`, which a later major version will require

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

* Supports Ruby 3.2, 3.3, 3.4, and 4.0
* Added `base64` and `cgi` as explicit runtime dependencies
* Migrated test suite from RSpec to Minitest

