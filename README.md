# simple_oauth

[![Gem Version](https://badge.fury.io/rb/simple_oauth.svg)](https://badge.fury.io/rb/simple_oauth)
[![Test](https://github.com/laserlemon/simple_oauth/actions/workflows/test.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/test.yml)
[![Mutant](https://github.com/laserlemon/simple_oauth/actions/workflows/mutant.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/mutant.yml)
[![Lint](https://github.com/laserlemon/simple_oauth/actions/workflows/lint.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/lint.yml)
[![Typecheck](https://github.com/laserlemon/simple_oauth/actions/workflows/typecheck.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/typecheck.yml)
[![Yardstick](https://github.com/laserlemon/simple_oauth/actions/workflows/yardstick.yml/badge.svg)](https://github.com/laserlemon/simple_oauth/actions/workflows/yardstick.yml)

Simply builds and verifies OAuth 1.0 headers per [RFC 5849](https://tools.ietf.org/html/rfc5849), and builds OAuth 2.0 requests per [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), and [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009).

Neither makes HTTP requests: you send what it builds with the HTTP client of your choice.

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

### Signing a Request

`Header.from_request` takes the method, URL, and parameters from a request object, such as a `Net::HTTPRequest`. Query parameters are always signed, a form-encoded body is signed as parameters, and any other body is hashed into `oauth_body_hash`:

```ruby
request = Net::HTTP::Post.new(URI("https://api.example.com/statuses"))
request.set_form_data(status: "Hello")
request["Authorization"] = SimpleOAuth::Header.from_request(request,
  consumer_key: "key",
  consumer_secret: "secret"
).to_s
```

### Repeated Parameters

Pass an Array of values, or an Array of key-value pairs, when a key repeats:

```ruby
header = SimpleOAuth::Header.new(:post, url, {"ids" => %w[1 2]},
  consumer_key: "key",
  consumer_secret: "secret"
)

header = SimpleOAuth::Header.new(:post, url, [["ids", "1"], ["ids", "2"]],
  consumer_key: "key",
  consumer_secret: "secret"
)
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
SimpleOAuth::Signature.registered_methods
# => ["hmac_sha1", "hmac_sha256", "rsa_sha1", "rsa_sha256", "plaintext", "hmac_sha512"]
```

### OAuth Request Body Hash

For non-form-encoded request bodies (e.g., JSON), pass the body as the fifth parameter to compute `oauth_body_hash`, which is hashed with the signature method's algorithm. Form-encoded bodies are signed by passing their parameters as `params` instead.

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

Parse OAuth credentials from a form-encoded POST body, or from a query string:

```ruby
parsed = SimpleOAuth::Header.parse_form_body('oauth_consumer_key=key&oauth_signature=sig&status=hello')
# => {consumer_key: "key", signature: "sig"}

parsed = SimpleOAuth::Header.parse_query("oauth_consumer_key=key&status=hello")
# => {consumer_key: "key"}
```

### Verifying Signatures

```ruby
# Parse incoming Authorization header
header = SimpleOAuth::Header.new(:get, request_url, params, authorization_header)

# Verify the signature
header.valid?(consumer_secret: "secret", token_secret: "token_secret")
# => true
```

Verifying compares signatures in constant time and leaves the header's own options untouched, so the secrets stay with the caller.

RSA signatures verify with the client's public key, which is all a server has:

```ruby
header.valid?(consumer_secret: File.read("client_public_key.pem"))
```

Custom signature methods that cannot be verified by recomputing the signature register a `verify` block:

```ruby
SimpleOAuth::Signature.register("RSA-SHA512", rsa: true,
  verify: ->(key, signature_base, signature) {
    OpenSSL::PKey::RSA.new(key).verify("SHA512", SimpleOAuth::Signature.decode_base64(signature), signature_base)
  }) do |private_key_pem, signature_base|
  SimpleOAuth::Signature.encode_base64(OpenSSL::PKey::RSA.new(private_key_pem).sign("SHA512", signature_base))
end
```

## OAuth 2.0

`SimpleOAuth::OAuth2::Client` builds authorization URLs and the requests for its token and revocation endpoints. Each request is a `SimpleOAuth::OAuth2::Request` with a `method`, `url`, `headers`, and form-encoded `body`, ready to send with any HTTP client.

A client with a secret is confidential and authenticates with HTTP Basic, or in the request body with `auth_method: :client_secret_post`. A client without a secret is public and sends only its `client_id`.

### Authorization Code Flow with PKCE

```ruby
require "net/http"
require "simple_oauth"

client = SimpleOAuth::OAuth2::Client.new(
  client_id: "client_id",
  client_secret: "client_secret", # omit for a public client
  authorization_endpoint: "https://x.com/i/oauth2/authorize",
  token_endpoint: "https://api.x.com/2/oauth2/token",
  revocation_endpoint: "https://api.x.com/2/oauth2/revoke"
)

# 1. Send the user to authorize the client
pkce = SimpleOAuth::OAuth2::PKCE.generate
state = SecureRandom.hex
redirect_to client.authorization_url(
  redirect_uri: "https://app.example/callback",
  state: state,
  scope: %w[tweet.read users.read offline.access],
  pkce: pkce
)

# 2. Exchange the code the user returns with for a token
request = client.authorization_code_request(
  code: params[:code],
  redirect_uri: "https://app.example/callback",
  code_verifier: pkce.verifier
)
response = Net::HTTP.post(URI(request.url), request.body, request.headers)
token = SimpleOAuth::OAuth2::Token.from_response(status: response.code, body: response.body)

token.access_token  # => "..."
token.refresh_token # => "..."
token.expires_at    # => 2026-09-11 14:00:00 +0000
```

`Token.from_response` raises `SimpleOAuth::OAuth2::Error` for an error response, with the endpoint's `code`, `description`, `uri`, and HTTP `status`.

### Refreshing, Client Credentials, and Revocation

```ruby
client.refresh_token_request(refresh_token: token.refresh_token)
client.client_credentials_request(scope: "read") # confidential clients only
client.revocation_request(token: token.refresh_token, token_type_hint: "refresh_token")

token.expired?(leeway: 30) # => true within 30 seconds of expiring
```

A revocation endpoint answers 200 when the token is revoked. For any other response, `SimpleOAuth::OAuth2::Error.from_response(status:, body:)` describes the failure.

## Errors

Every error the library raises descends from `SimpleOAuth::Error`, so one rescue covers all of them:

```ruby
begin
  token = SimpleOAuth::OAuth2::Token.from_response(status: response.code, body: response.body)
rescue SimpleOAuth::Error => error
  # SimpleOAuth::OAuth2::Error, SimpleOAuth::ParseError, or SimpleOAuth::InvalidOptionsError
end
```

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/laserlemon/simple_oauth.

This project conforms to [Standard Ruby](https://github.com/standardrb/standard). Patches that don’t maintain that standard will not be accepted.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
