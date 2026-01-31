require "test_helper"

module SimpleOAuth
  # Tests for signature validation using RFC 5849 credentials.
  class HeaderValidationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #valid? tests - HMAC-SHA1

    def test_valid_hmac_sha1_is_not_valid_without_secrets
      secrets = {consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET}
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, header)

      refute_predicate parsed_header, :valid?
    end

    def test_valid_hmac_sha1_is_valid_with_secrets
      secrets = {consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET}
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #valid? tests - RSA-SHA1

    def test_valid_rsa_sha1_raises_type_error_without_private_key
      secrets = {consumer_secret: rsa_private_key}
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {},
        secrets.merge(signature_method: "RSA-SHA1"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, header)
      assert_raises(TypeError) { parsed_header.valid? }
    end

    def test_valid_rsa_sha1_is_valid_with_private_key
      secrets = {consumer_secret: rsa_private_key}
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {},
        secrets.merge(signature_method: "RSA-SHA1"))
      parsed_header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, header)

      assert parsed_header.valid?(secrets)
    end

    # #valid? tests - PLAINTEXT

    def test_valid_plaintext_is_not_valid_without_secrets
      # RFC 5849 Section 2.1 - PLAINTEXT example credentials
      secrets = {consumer_secret: RFC5849::PlaintextExample::CONSUMER_SECRET,
                 token_secret: RFC5849::PlaintextExample::TOKEN_SECRET}
      header = SimpleOAuth::Header.new(:get, "http://server.example.com/resource", {},
        secrets.merge(signature_method: "PLAINTEXT"))
      parsed_header = SimpleOAuth::Header.new(:get, "http://server.example.com/resource", {}, header)

      refute_predicate parsed_header, :valid?
    end

    def test_valid_plaintext_is_valid_with_secrets
      # RFC 5849 Section 2.1 - PLAINTEXT example credentials
      secrets = {consumer_secret: RFC5849::PlaintextExample::CONSUMER_SECRET,
                 token_secret: RFC5849::PlaintextExample::TOKEN_SECRET}
      header = SimpleOAuth::Header.new(:get, "http://server.example.com/resource", {},
        secrets.merge(signature_method: "PLAINTEXT"))
      parsed_header = SimpleOAuth::Header.new(:get, "http://server.example.com/resource", {}, header)

      assert parsed_header.valid?(secrets)
    end

    def test_valid_restores_original_options_after_validation
      secrets = {consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET}
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, header)
      original_options = parsed_header.options.dup

      parsed_header.valid?(secrets)

      assert_equal original_options, parsed_header.options
    end

    def test_valid_returns_false_when_signature_does_not_match
      secrets = {consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET}
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, secrets)
      parsed_header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos", {}, header)

      refute parsed_header.valid?(consumer_secret: "WRONG_SECRET", token_secret: "WRONG_TOKEN")
    end
  end
end
