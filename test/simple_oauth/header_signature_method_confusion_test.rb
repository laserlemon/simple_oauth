# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests that a received header cannot choose the signature method it is verified with
  class HeaderSignatureMethodConfusionTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def setup
      @public_key = OpenSSL::PKey::RSA.new(rsa_private_key).public_key.to_pem
    end

    def test_an_hmac_signature_keyed_with_the_public_key_is_not_valid_for_rsa
      forged = build_header(consumer_secret: @public_key, signature_method: "HMAC-SHA1")

      refute received(forged).valid?(consumer_secret: @public_key, signature_method: "RSA-SHA1")
    end

    def test_a_plaintext_signature_of_the_public_key_is_not_valid_for_rsa
      forged = build_header(consumer_secret: @public_key, signature_method: "PLAINTEXT")

      refute received(forged).valid?(consumer_secret: @public_key, signature_method: "RSA-SHA1")
    end

    def test_a_plaintext_signature_is_not_valid_when_hmac_is_expected
      signed = build_header(signature_method: "PLAINTEXT")

      refute received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA1")
    end

    def test_a_plaintext_signature_is_valid_when_expected
      signed = build_header(signature_method: "PLAINTEXT")

      assert received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "PLAINTEXT")
    end

    def test_an_rsa_signature_is_not_valid_when_hmac_is_expected
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")

      refute received(signed).valid?(consumer_secret: @public_key, signature_method: "HMAC-SHA1")
    end

    def test_a_weaker_hash_is_not_valid_when_a_stronger_one_is_expected
      signed = build_header(signature_method: "HMAC-SHA1")

      valid = received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA256")

      assert_same false, valid
    end

    def test_the_expected_method_is_compared_without_regard_to_case
      signed = build_header(signature_method: "hmac-sha256")

      assert received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA256")
    end

    def test_a_header_without_a_signature_method_is_not_valid
      header = 'OAuth oauth_consumer_key="key", oauth_nonce="n", oauth_signature="sig", oauth_timestamp="1"'

      received = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header)

      refute received.valid?(consumer_secret: "s", signature_method: "HMAC-SHA1")
    end

    def test_a_signature_made_with_another_method_than_the_header_claims_is_not_valid
      claimed = received(build_header(signature_method: "HMAC-SHA256"))
      sha1 = Signature.sign("HMAC-SHA1", "#{RFC5849::CONSUMER_SECRET}&", claimed.send(:signature_base))
      mismatched = claimed.to_s.sub(/oauth_signature="[^"]*"/, %(oauth_signature="#{Header.escape(sha1)}"))

      refute received(mismatched).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA1")
    end

    def test_verifying_without_naming_a_signature_method_raises
      error = assert_raises(ArgumentError) { received(build_header).valid?(consumer_secret: RFC5849::CONSUMER_SECRET) }

      assert_equal 'Name the signature method to verify with, such as signature_method: "HMAC-SHA1"', error.message
    end

    def test_an_unregistered_method_the_header_also_claims_raises
      header = 'OAuth oauth_consumer_key="key", oauth_nonce="n", oauth_signature="sig", ' \
               'oauth_signature_method="HMAC-MD5", oauth_timestamp="1"'
      received = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header)

      error = assert_raises(ArgumentError) { received.valid?(consumer_secret: "s", signature_method: "HMAC-MD5") }

      assert_match(/\AUnknown signature method: HMAC-MD5/, error.message)
    end

    def test_an_unregistered_expected_method_raises
      signed = build_header

      error = assert_raises(ArgumentError) do
        received(signed).valid?(consumer_secret: "s", signature_method: "HMAC-MD5")
      end

      assert_equal "Unknown signature method: HMAC-MD5", error.message
    end

    private

    def received(header)
      SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header.to_s)
    end
  end
end
