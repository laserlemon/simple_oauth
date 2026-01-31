require "test_helper"

module SimpleOAuth
  # Integration tests using credentials and URLs from RFC 5849.
  # See https://www.rfc-editor.org/rfc/rfc5849
  #
  # Note: Our library includes oauth_version="1.0" by default, which the
  # RFC examples omit. This means our signatures differ from the RFC
  # examples, but we verify consistency and correctness.
  class HeaderSignatureIntegrationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # HMAC-SHA1 tests using RFC 5849 Section 1.2 credentials

    def test_hmac_sha1_produces_valid_signature_for_get
      # RFC 5849 Section 1.2 - Accessing Protected Resource
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos",
        {file: "vacation.jpg", size: "original"}, rfc_resource_request_options)
      parsed = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos",
        {file: "vacation.jpg", size: "original"}, header.to_s)

      assert parsed.valid?(consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET)
    end

    def test_hmac_sha1_produces_valid_signature_for_post
      # RFC 5849 Section 1.2 - Token Request
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/token", {},
        rfc_token_request_options)
      parsed = SimpleOAuth::Header.new(:post, "https://photos.example.net/token", {}, header.to_s)

      assert parsed.valid?(consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TEMP_TOKEN_SECRET)
    end

    def test_hmac_sha1_includes_callback_in_signature
      # RFC 5849 Section 1.2 - Temporary Credentials Request includes callback
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/initiate", {},
        rfc_temporary_credentials_options)

      assert_includes header.to_s, 'oauth_callback="http%3A%2F%2Fprinter.example.com%2Fready"'
    end

    def test_hmac_sha1_includes_verifier_in_signature
      # RFC 5849 Section 1.2 - Token Request includes verifier
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/token", {},
        rfc_token_request_options)

      assert_includes header.to_s, "oauth_verifier=\"#{RFC5849::VERIFIER}\""
    end

    # RSA-SHA1 tests using RFC 5849 Section 1.2 credentials

    def test_rsa_sha1_produces_valid_signature
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos",
        {file: "vacation.jpg", size: "original"}, rsa_sha1_options)
      parsed = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos",
        {file: "vacation.jpg", size: "original"}, header.to_s)

      assert parsed.valid?(consumer_secret: rsa_private_key)
    end

    # PLAINTEXT tests using RFC 5849 Section 2.1 credentials

    def test_plaintext_produces_valid_signature
      # RFC 5849 Section 2.1 - PLAINTEXT Temporary Credentials Request
      header = SimpleOAuth::Header.new(:post, "http://server.example.com/request_temp_credentials", {},
        rfc_plaintext_options)
      parsed = SimpleOAuth::Header.new(:post, "http://server.example.com/request_temp_credentials", {},
        header.to_s)

      assert parsed.valid?(consumer_secret: RFC5849::PlaintextExample::CONSUMER_SECRET)
    end

    def test_plaintext_signature_is_escaped_secret
      header = SimpleOAuth::Header.new(:post, "http://server.example.com/request_temp_credentials", {},
        rfc_plaintext_options)

      # PLAINTEXT signature is consumer_secret&token_secret (no token_secret here)
      assert_equal "#{RFC5849::PlaintextExample::CONSUMER_SECRET}&", header.signed_attributes[:oauth_signature]
    end

    private

    # RFC 5849 Section 1.2 - Temporary Credentials Request
    def rfc_temporary_credentials_options
      {
        consumer_key: RFC5849::CONSUMER_KEY,
        consumer_secret: RFC5849::CONSUMER_SECRET,
        signature_method: "HMAC-SHA1",
        timestamp: "137131200",
        nonce: "wIjqoS",
        callback: RFC5849::PRINTER_CALLBACK
      }
    end

    # RFC 5849 Section 1.2 - Token Request
    def rfc_token_request_options
      {
        consumer_key: RFC5849::CONSUMER_KEY,
        consumer_secret: RFC5849::CONSUMER_SECRET,
        token: RFC5849::TEMP_TOKEN,
        token_secret: RFC5849::TEMP_TOKEN_SECRET,
        signature_method: "HMAC-SHA1",
        timestamp: "137131201",
        nonce: "walatlh",
        verifier: RFC5849::VERIFIER
      }
    end

    # RFC 5849 Section 1.2 - Accessing Protected Resource
    def rfc_resource_request_options
      {
        consumer_key: RFC5849::CONSUMER_KEY,
        consumer_secret: RFC5849::CONSUMER_SECRET,
        token: RFC5849::TOKEN,
        token_secret: RFC5849::TOKEN_SECRET,
        signature_method: "HMAC-SHA1",
        timestamp: "137131202",
        nonce: "chapoH"
      }
    end

    # RSA-SHA1 using RFC 5849 credentials
    def rsa_sha1_options
      {
        consumer_key: RFC5849::CONSUMER_KEY,
        consumer_secret: rsa_private_key,
        nonce: "13917289812797014437",
        signature_method: "RSA-SHA1",
        timestamp: "1196666512"
      }
    end

    # RFC 5849 Section 2.1 - PLAINTEXT example
    def rfc_plaintext_options
      {
        consumer_key: RFC5849::PlaintextExample::CONSUMER_KEY,
        consumer_secret: RFC5849::PlaintextExample::CONSUMER_SECRET,
        signature_method: "PLAINTEXT",
        timestamp: "137131200",
        nonce: "7d8f3e4a",
        callback: RFC5849::PlaintextExample::CALLBACK
      }
    end
  end
end
