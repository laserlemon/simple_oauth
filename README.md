# simple_oauth

[![Gem Version](https://badge.fury.io/rb/simple_oauth.svg)](https://badge.fury.io/rb/simple_oauth)
[![Test](https://github.com/laserlemon/simple_oauth/actions/workflows/test.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/test.yml)
[![Mutant](https://github.com/laserlemon/simple_oauth/actions/workflows/mutant.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/mutant.yml)
[![Lint](https://github.com/laserlemon/simple_oauth/actions/workflows/lint.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/lint.yml)
[![Typecheck](https://github.com/laserlemon/simple_oauth/actions/workflows/typecheck.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/typecheck.yml)
[![Yardstick](https://github.com/laserlemon/simple_oauth/actions/workflows/yardstick.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/yardstick.yml)

Simply builds and verifies OAuth headers per [RFC 5849](https://tools.ietf.org/html/rfc5849)

## Installation

Install the gem and add to the application's Gemfile by executing:

    $ bundle add simple_oauth

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install simple_oauth

## Usage

### Building an OAuth Header

```ruby
require "simple_oauth"

header = SimpleOAuth::Header.new(
  :get,
  "https://api.example.com/resource",
  {status: "Hello"},
  consumer_key: "consumer_key",
  consumer_secret: "consumer_secret",
  token: "access_token",
  token_secret: "token_secret"
)

header.to_s
# => "OAuth oauth_consumer_key=\"consumer_key\", oauth_nonce=\"...\", ..."
```

### Signature Methods

Built-in signature methods: `HMAC-SHA1` (default), `HMAC-SHA256`, `RSA-SHA1`, `RSA-SHA256`, and `PLAINTEXT`.

```ruby
# Using HMAC-SHA256
header = SimpleOAuth::Header.new(:get, url, params,
  consumer_key: "key",
  consumer_secret: "secret",
  signature_method: "HMAC-SHA256"
)

# Using RSA-SHA1 (pass PEM-encoded private key as consumer_secret)
header = SimpleOAuth::Header.new(:get, url, params,
  consumer_key: "key",
  consumer_secret: File.read("private_key.pem"),
  signature_method: "RSA-SHA1"
)
```

### Custom Signature Methods

Register custom signature methods at runtime:

```ruby
SimpleOAuth::Signature.register("HMAC-SHA512") do |secret, signature_base|
  Base64.encode64(OpenSSL::HMAC.digest("SHA512", secret, signature_base)).delete("\n")
end

# Check registered methods
SimpleOAuth::Signature.registered?("HMAC-SHA512") # => true
SimpleOAuth::Signature.methods # => ["hmac_sha1", "hmac_sha256", "rsa_sha1", "rsa_sha256", "plaintext", "hmac_sha512"]
```

### OAuth Request Body Hash

For non-form-encoded request bodies (e.g., JSON), pass the body as the fifth parameter to compute `oauth_body_hash`:

```ruby
json_body = '{"text": "Hello, World!"}'

header = SimpleOAuth::Header.new(:post, url, {},
  {consumer_key: "key", consumer_secret: "secret"},
  json_body
)
```

### Realm Parameter

Include a realm in the Authorization header:

```ruby
header = SimpleOAuth::Header.new(:get, url, params,
  consumer_key: "key",
  consumer_secret: "secret",
  realm: "Example"
)
# => "OAuth realm=\"Example\", oauth_consumer_key=\"key\", ..."
```

### Parsing OAuth Headers

Parse an OAuth Authorization header:

```ruby
parsed = SimpleOAuth::Header.parse('OAuth oauth_consumer_key="key", oauth_signature="sig"')
# => {consumer_key: "key", signature: "sig"}
```

Parse OAuth credentials from a form-encoded POST body:

```ruby
parsed = SimpleOAuth::Header.parse_form_body('oauth_consumer_key=key&oauth_signature=sig&status=hello')
# => {consumer_key: "key", signature: "sig"}
```

### Verifying Signatures

```ruby
# Parse incoming Authorization header
header = SimpleOAuth::Header.new(:get, request_url, params, authorization_header)

# Verify the signature
header.valid?(consumer_secret: "secret", token_secret: "token_secret")
# => true
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/laserlemon/simple_oauth.

This project conforms to [Standard Ruby](https://github.com/standardrb/standard). Patches that don’t maintain that standard will not be accepted.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
