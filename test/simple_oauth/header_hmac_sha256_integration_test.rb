require "test_helper"

module SimpleOAuth
  # HMAC-SHA256 integration tests using RFC 5849 credentials.
  # Note: HMAC-SHA256 is not defined in RFC 5849, but is a common extension.
  class HeaderHmacSha256IntegrationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_hmac_sha256_signature_produces_valid_signature_for_get
      # Using RFC 5849 Section 1.2 credentials with HMAC-SHA256
      header = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos",
        {file: "vacation.jpg", size: "original"}, hmac_sha256_get_options)
      parsed = SimpleOAuth::Header.new(:get, "https://photos.example.net/photos",
        {file: "vacation.jpg", size: "original"}, header.to_s)

      assert parsed.valid?(consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TOKEN_SECRET)
    end

    def test_hmac_sha256_signature_produces_valid_signature_for_post
      # Using RFC 5849 Section 1.2 credentials with HMAC-SHA256
      header = SimpleOAuth::Header.new(:post, "https://photos.example.net/token", {},
        hmac_sha256_post_options)
      parsed = SimpleOAuth::Header.new(:post, "https://photos.example.net/token", {}, header.to_s)

      assert parsed.valid?(consumer_secret: RFC5849::CONSUMER_SECRET, token_secret: RFC5849::TEMP_TOKEN_SECRET)
    end

    private

    def hmac_sha256_get_options
      {
        consumer_key: RFC5849::CONSUMER_KEY,
        consumer_secret: RFC5849::CONSUMER_SECRET,
        token: RFC5849::TOKEN,
        token_secret: RFC5849::TOKEN_SECRET,
        signature_method: "HMAC-SHA256",
        timestamp: "137131202",
        nonce: "chapoH"
      }
    end

    def hmac_sha256_post_options
      {
        consumer_key: RFC5849::CONSUMER_KEY,
        consumer_secret: RFC5849::CONSUMER_SECRET,
        token: RFC5849::TEMP_TOKEN,
        token_secret: RFC5849::TEMP_TOKEN_SECRET,
        signature_method: "HMAC-SHA256",
        timestamp: "137131201",
        nonce: "walatlh",
        verifier: RFC5849::VERIFIER
      }
    end
  end
end
