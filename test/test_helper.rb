$LOAD_PATH.unshift File.expand_path("../lib", __dir__)

require "simplecov"

SimpleCov.start do
  enable_coverage :branch
  add_filter "/test/"
  minimum_coverage line: 100, branch: 100
end

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
    PHOTOS_HOST = "photos.example.net".freeze
    PHOTOS_BASE_URL = "https://#{PHOTOS_HOST}".freeze
    PHOTOS_URL = "#{PHOTOS_BASE_URL}/photos".freeze
    PRINTER_HOST = "printer.example.com".freeze
    PRINTER_CALLBACK = "http://#{PRINTER_HOST}/ready".freeze

    # Section 1.2 - Client credentials (printer application)
    CONSUMER_KEY = "dpf43f3p2l4k3l03".freeze
    CONSUMER_SECRET = "kd94hf93k423kf44".freeze

    # Section 1.2 - Temporary credentials
    TEMP_TOKEN = "hh5s93j4hdidpola".freeze
    TEMP_TOKEN_SECRET = "hdhd0244k9j7ao03".freeze

    # Section 1.2 - Token credentials
    TOKEN = "nnch734d00sl2jdk".freeze
    TOKEN_SECRET = "pfkkdhi9sl3r4s00".freeze

    # Section 1.2 - Verifier
    VERIFIER = "hfdp7dh39dks9884".freeze

    # Section 3.1 / 3.4.1 - Signature example
    module SignatureExample
      HOST = "example.com".freeze
      BASE_URL = "http://#{HOST}".freeze
      CONSUMER_KEY = "9djdj82h48djs9d2".freeze
      CONSUMER_SECRET = "j49sk3j29djd".freeze
      TOKEN = "kkk9d7dh3k39sjv7".freeze
      TOKEN_SECRET = "dh893hdasih9".freeze
      TIMESTAMP = "137131201".freeze
      NONCE = "7d8f3e4a".freeze
    end

    # Section 3.5.1 - Authorization header example
    module HeaderExample
      CONSUMER_KEY = "0685bd9184jfhq22".freeze
      CONSUMER_SECRET = "kd94hf93k423kf44".freeze
      TOKEN = "ad180jjd733klru7".freeze
      TOKEN_SECRET = "pfkkdhi9sl3r4s00".freeze
      TIMESTAMP = "137131200".freeze
      NONCE = "4572616e48616d6d65724c61686176".freeze

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
      HOST = "server.example.com".freeze
      BASE_URL = "http://#{HOST}".freeze
      CONSUMER_KEY = "jd83jd92dhsh93js".freeze
      CONSUMER_SECRET = "ja893SD9".freeze
      CALLBACK = "http://client.example.net/cb?x=1".freeze
      TOKEN = "hdk48Djdsa".freeze
      TOKEN_SECRET = "xyz4992k83j47x0b".freeze
      VERIFIER = "473f82d3".freeze
    end
  end
end
