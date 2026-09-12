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

