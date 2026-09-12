require "net/http"
require "test_helper"

module SimpleOAuth
  # Tests that verification checks the received body against the signed oauth_body_hash
  class HeaderBodyVerificationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    SECRETS = {consumer_secret: RFC5849::CONSUMER_SECRET}.freeze
    BODY = '{"status":"Hello Ladies + Gentlemen"}'.freeze
    TAMPERED_BODY = '{"status":"Goodbye Ladies + Gentlemen"}'.freeze

    def test_a_body_matching_the_signed_hash_is_valid
      assert valid?(signed_authorization, BODY)
    end

    def test_a_tampered_body_is_not_valid
      refute valid?(signed_authorization, TAMPERED_BODY)
    end

    def test_a_body_matching_a_sha256_hash_is_valid
      assert valid?(signed_authorization("HMAC-SHA256"), BODY)
    end

    def test_a_tampered_body_is_not_valid_under_sha256
      refute valid?(signed_authorization("HMAC-SHA256"), TAMPERED_BODY)
    end

    def test_a_body_the_signature_leaves_uncovered_is_valid
      assert valid?(build_header(:post).to_s, BODY)
    end

    def test_a_signed_hash_without_a_body_is_valid
      header = SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {}, signed_authorization)

      assert header.valid?(SECRETS)
    end

    private

    def signed_authorization(signature_method = SimpleOAuth::Header::DEFAULT_SIGNATURE_METHOD)
      options = {consumer_key: RFC5849::CONSUMER_KEY, consumer_secret: RFC5849::CONSUMER_SECRET,
                 signature_method: signature_method}
      SimpleOAuth::Header.new(:post, RFC5849::PHOTOS_URL, {}, options, BODY).to_s
    end

    def valid?(authorization, body)
      request = Net::HTTP::Post.new(URI(RFC5849::PHOTOS_URL), "Content-Type" => "application/json")
      request.body = body
      SimpleOAuth::Header.from_request(request, authorization).valid?(SECRETS)
    end
  end
end
