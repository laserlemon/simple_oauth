# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests that a received header cannot choose a signature method its verifying key does not fit
  class HeaderSignatureMethodConfusionTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def setup
      @public_key = OpenSSL::PKey::RSA.new(rsa_private_key).public_key.to_pem
      @deprecated = Warning[:deprecated]
    end

    def teardown
      Warning[:deprecated] = @deprecated
    end

    # Without a signature_method, the claimed method must fit the key

    def test_an_hmac_signature_keyed_with_the_public_key_is_not_valid
      forged = build_header(consumer_secret: @public_key, signature_method: "HMAC-SHA1")

      refute received(forged).valid?(consumer_secret: @public_key)
    end

    def test_a_plaintext_signature_of_the_public_key_is_not_valid
      forged = build_header(consumer_secret: @public_key, signature_method: "PLAINTEXT")

      refute received(forged).valid?(consumer_secret: @public_key)
    end

    def test_an_rsa_signature_is_valid_with_the_public_key
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA256")

      assert received(signed).valid?(consumer_secret: @public_key)
    end

    def test_an_hmac_signature_is_valid_with_a_shared_secret
      assert received(build_header).valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
    end

    def test_an_rsa_signature_is_not_valid_with_a_shared_secret
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")

      refute received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
    end

    def test_a_plaintext_signature_is_not_valid_unless_named
      signed = build_header(signature_method: "PLAINTEXT")

      refute received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
    end

    def test_a_plaintext_signature_in_lowercase_is_not_valid_unless_named
      signed = build_header(signature_method: "plaintext")

      refute received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
    end

    def test_an_unregistered_claimed_method_is_not_valid
      header = 'OAuth oauth_consumer_key="key", oauth_nonce="n", oauth_signature="sig", ' \
               'oauth_signature_method="HMAC-MD5", oauth_timestamp="1"'

      refute SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header).valid?(consumer_secret: "s")
    end

    def test_a_header_without_a_signature_method_is_not_valid
      header = 'OAuth oauth_consumer_key="key", oauth_nonce="n", oauth_signature="sig", oauth_timestamp="1"'

      refute SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header).valid?(consumer_secret: "s")
    end

    def test_verifying_without_a_signature_method_is_deprecated
      Warning[:deprecated] = true

      assert_output(nil, /valid\? without a signature_method is deprecated. Name the method to verify with, /) do
        received(build_header).valid?(consumer_secret: RFC5849::CONSUMER_SECRET)
      end
    end

    def test_the_deprecation_is_silent_unless_deprecation_warnings_are_on
      Warning[:deprecated] = false

      assert_output(nil, "") { received(build_header).valid?(consumer_secret: RFC5849::CONSUMER_SECRET) }
    end

    # With a signature_method, the header must claim it

    def test_an_hmac_signature_keyed_with_the_public_key_is_not_valid_for_rsa
      forged = build_header(consumer_secret: @public_key, signature_method: "HMAC-SHA1")

      refute received(forged).valid?(consumer_secret: @public_key, signature_method: "RSA-SHA1")
    end

    def test_a_plaintext_signature_is_valid_when_named
      signed = build_header(signature_method: "PLAINTEXT")

      assert received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "PLAINTEXT")
    end

    def test_a_weaker_hash_is_not_valid_when_a_stronger_one_is_named
      refute received(build_header).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA256")
    end

    def test_the_named_method_is_compared_without_regard_to_case
      signed = build_header(signature_method: "hmac-sha256")

      assert received(signed).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA256")
    end

    def test_naming_a_method_is_not_deprecated
      Warning[:deprecated] = true

      assert_output(nil, "") do
        received(build_header).valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA1")
      end
    end

    def test_a_header_without_a_signature_method_is_not_valid_for_a_named_method
      header = 'OAuth oauth_consumer_key="key", oauth_nonce="n", oauth_signature="sig", oauth_timestamp="1"'
      received = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header)

      refute received.valid?(consumer_secret: "s", signature_method: "HMAC-SHA1")
    end

    def test_naming_an_unregistered_method_raises
      error = assert_raises(ArgumentError) do
        received(build_header).valid?(consumer_secret: "s", signature_method: "HMAC-MD5")
      end

      assert_equal "Unknown signature method: HMAC-MD5", error.message
    end

    private

    def received(header)
      SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header.to_s)
    end
  end
end
