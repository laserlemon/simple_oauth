## [Unreleased]

### Added

* Document passing `Header` parameters as an Array of key-value pairs when a key repeats

### Fixed

* Accept an Array of key-value pairs as `Header` parameters in the RBS signatures, which already worked at runtime

## [Unreleased]

### Added

* `Signature.verify` and a `verify:` option on `Signature.register`, for signature methods that cannot be verified by recomputing the signature
* `Signature.decode_base64`

### Fixed

* Sign a parameter whose value is an Array as one parameter per value, as a repeated parameter; the Array was previously signed as its Ruby representation
* Verify RSA signatures with the signer's public key, which is all a verifier has; `Header#valid?` previously recomputed the signature and so needed the private key

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

