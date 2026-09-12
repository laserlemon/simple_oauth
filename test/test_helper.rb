# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "simplecov"

SimpleCov.start do
  enable_coverage :branch
  skip "/test/"
  minimum_coverage line: 100, branch: 100
end

require "base64"
require "minitest/autorun"
require "simple_oauth"

# Define a no-op cover method for regular test runs (mutant-minitest defines this when running mutations)
Minitest::Test.define_singleton_method(:cover) { |*| nil } unless Minitest::Test.respond_to?(:cover)

module TestHelpers
  PRIVATE_KEY_PATH = File.expand_path("fixtures/rsa-private-key", __dir__)

  def rsa_private_key
    @rsa_private_key ||= File.read(PRIVATE_KEY_PATH)
  end

  # Factory method to build a Header with common defaults
  def build_header(method = :get, url = RFC5849::PHOTOS_URL, params = {}, **options)
    defaults = {
      consumer_key: RFC5849::CONSUMER_KEY,
      consumer_secret: RFC5849::CONSUMER_SECRET
    }
    SimpleOAuth::Header.new(method, url, params, defaults.merge(options))
  end

  # Factory method to build a Header with fixed nonce/timestamp for deterministic tests
  def build_header_with_fixed_credentials(method = :get, url = RFC5849::PHOTOS_URL, params = {}, **options)
    defaults = {
      consumer_key: RFC5849::CONSUMER_KEY,
      consumer_secret: RFC5849::CONSUMER_SECRET,
      nonce: "chapoH",
      timestamp: "137131202"
    }
    SimpleOAuth::Header.new(method, url, params, defaults.merge(options))
  end

  # RFC 5849 Example Constants
  # See https://www.rfc-editor.org/rfc/rfc5849 for complete examples
  module RFC5849
    # Section 1.2 - Printer/Photos example endpoints
    PHOTOS_HOST = "photos.example.net"
    PHOTOS_BASE_URL = "https://#{PHOTOS_HOST}".freeze
    PHOTOS_URL = "#{PHOTOS_BASE_URL}/photos".freeze
    PRINTER_HOST = "printer.example.com"
    PRINTER_CALLBACK = "http://#{PRINTER_HOST}/ready".freeze

    # Section 1.2 - Client credentials (printer application)
    CONSUMER_KEY = "dpf43f3p2l4k3l03"
    CONSUMER_SECRET = "kd94hf93k423kf44"

    # Section 1.2 - Temporary credentials
    TEMP_TOKEN = "hh5s93j4hdidpola"
    TEMP_TOKEN_SECRET = "hdhd0244k9j7ao03"

    # Section 1.2 - Token credentials
    TOKEN = "nnch734d00sl2jdk"
    TOKEN_SECRET = "pfkkdhi9sl3r4s00"

    # Section 1.2 - Verifier
    VERIFIER = "hfdp7dh39dks9884"

    # Section 3.1 / 3.4.1 - Signature example
    module SignatureExample
      HOST = "example.com"
      BASE_URL = "http://#{HOST}".freeze
      CONSUMER_KEY = "9djdj82h48djs9d2"
      CONSUMER_SECRET = "j49sk3j29djd"
      TOKEN = "kkk9d7dh3k39sjv7"
      TOKEN_SECRET = "dh893hdasih9"
      TIMESTAMP = "137131201"
      NONCE = "7d8f3e4a"
    end

    # Section 3.5.1 - Authorization header example
    module HeaderExample
      CONSUMER_KEY = "0685bd9184jfhq22"
      CONSUMER_SECRET = "kd94hf93k423kf44"
      TOKEN = "ad180jjd733klru7"
      TOKEN_SECRET = "pfkkdhi9sl3r4s00"
      TIMESTAMP = "137131200"
      NONCE = "4572616e48616d6d65724c61686176"

      # Complete options hash for tests
      OPTIONS = {
        consumer_key: CONSUMER_KEY,
        consumer_secret: CONSUMER_SECRET,
        token: TOKEN,
        token_secret: TOKEN_SECRET,
        nonce: NONCE,
        timestamp: TIMESTAMP
      }.freeze
    end

    # Complete options hash for printer/photos example (Section 1.2)
    PHOTOS_OPTIONS = {
      consumer_key: CONSUMER_KEY,
      consumer_secret: CONSUMER_SECRET,
      nonce: "wIjqoS",
      timestamp: "137131200",
      callback: PRINTER_CALLBACK
    }.freeze

    # Section 2.1 - PLAINTEXT example
    module PlaintextExample
      HOST = "server.example.com"
      BASE_URL = "http://#{HOST}".freeze
      CONSUMER_KEY = "jd83jd92dhsh93js"
      CONSUMER_SECRET = "ja893SD9"
      CALLBACK = "http://client.example.net/cb?x=1"
      TOKEN = "hdk48Djdsa"
      TOKEN_SECRET = "xyz4992k83j47x0b"
      VERIFIER = "473f82d3"
    end
  end
end

# RFC 6749, RFC 7636, and RFC 7009 example values for the OAuth 2.0 builders
module OAuth2Examples
  CLIENT_ID = "s6BhdRkqt3"
  CLIENT_SECRET = "gX1fBat3bV"
  BASIC_AUTHORIZATION = "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW"
  AUTHORIZATION_ENDPOINT = "https://server.example.com/authorize"
  TOKEN_ENDPOINT = "https://server.example.com/token"
  REVOCATION_ENDPOINT = "https://server.example.com/revoke"
  REDIRECT_URI = "https://client.example.com/cb"
  CODE = "SplxlOBeZQQYbYS6WxSbIA"
  ACCESS_TOKEN = "2YotnFZFEjr1zCsicMWpAA"
  REFRESH_TOKEN = "tGzv3JOkF0XG5Qx2TlKWIA"
  VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  TOKEN_RESPONSE = '{"access_token":"2YotnFZFEjr1zCsicMWpAA","token_type":"example","expires_in":3600,' \
                   '"refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA","example_parameter":"example_value"}'

  def confidential_client(**)
    SimpleOAuth::OAuth2::Client.new(client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      authorization_endpoint: AUTHORIZATION_ENDPOINT, token_endpoint: TOKEN_ENDPOINT,
      revocation_endpoint: REVOCATION_ENDPOINT, **)
  end

  def public_client
    SimpleOAuth::OAuth2::Client.new(client_id: CLIENT_ID, authorization_endpoint: AUTHORIZATION_ENDPOINT,
      token_endpoint: TOKEN_ENDPOINT, revocation_endpoint: REVOCATION_ENDPOINT)
  end
end
