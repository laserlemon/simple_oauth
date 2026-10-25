# frozen_string_literal: true

require "net/http"
require "openssl"

# Inputs shared by the benchmarks. Every header takes a fixed nonce and
# timestamp, so each iteration signs exactly the same base string.
module DuelHelper
  # The OAuth 1.0 credentials and protocol values of RFC 5849 Section 3.5.1
  CREDENTIALS = {
    consumer_key: "0685bd9184jfhq22",
    consumer_secret: "kd94hf93k423kf44",
    token: "ad180jjd733klru7",
    token_secret: "pfkkdhi9sl3r4s00",
    nonce: "4572616e48616d6d65724c61686176",
    timestamp: "137131200"
  }.freeze

  # The secrets a server verifies those credentials' signatures with
  SECRETS = CREDENTIALS.slice(:consumer_secret, :token_secret).freeze

  # The endpoint the OAuth 1.0 benchmarks sign requests for
  URL = "https://api.example.com/1.1/statuses/update.json"

  # A 2048-bit RSA key, made for these benchmarks only
  RSA_KEY_PATH = File.expand_path("fixtures/rsa-private-key", __dir__)

  # A status update, the typical form-encoded request a client signs
  STATUS_PARAMS = {
    "status" => "Hello Ladies + Gentlemen, a signed OAuth request!",
    "include_entities" => "true"
  }.freeze

  # The OAuth 2.0 client of a confidential web app
  OAUTH2_CLIENT = {
    client_id: "s6BhdRkqt3",
    client_secret: "7Fjfp0ZBr1KtDRbnfVdmIw",
    authorization_endpoint: "https://server.example.com/authorize",
    token_endpoint: "https://server.example.com/token",
    revocation_endpoint: "https://server.example.com/revoke"
  }.freeze

  # The PKCE code verifier of RFC 7636 Appendix B
  PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW-gEXk-cXbE"

  module_function

  # OAuth 1.0 options with the fixed credentials, merged with any others
  def oauth(**options) = CREDENTIALS.merge(options)

  # The PEM of the benchmarks' RSA private key
  def rsa_private_key = File.read(RSA_KEY_PATH)

  # Many form parameters with long values, with some keys repeating,
  # for a large request such as a batch lookup
  def many_params(count)
    Array.new(count) { |i| ["param_#{i % (count / 2)}", "value #{i}: #{"Ünïcödé & reserved/chars? " * 4}"] }
  end
end
