require "test_helper"

module SimpleOAuth
  # Counts the RSA keys parsed, so a test can tell which secrets are parsed as keys
  module RSAKeyParseCount
    class << self
      attr_accessor :count
    end
    self.count = 0

    def new(...)
      RSAKeyParseCount.count += 1
      super
    end
  end
  OpenSSL::PKey::RSA.singleton_class.prepend(RSAKeyParseCount)

  # Tests that a verifying key fits the method a header claims, whichever encoding the key is in
  class HeaderVerificationKeyTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def setup
      @public_key = OpenSSL::PKey::RSA.new(rsa_private_key).public_key.to_pem
      @deprecated = Warning[:deprecated]
      Warning[:deprecated] = false
    end

    def teardown
      Warning[:deprecated] = @deprecated
    end

    def test_an_hmac_signature_keyed_with_a_der_public_key_is_not_valid
      der = OpenSSL::PKey::RSA.new(rsa_private_key).public_key.to_der
      forged = build_header(consumer_secret: der, signature_method: "HMAC-SHA1")

      refute received(forged).valid?(consumer_secret: der)
    end

    def test_an_rsa_signature_is_valid_with_a_der_public_key
      der = OpenSSL::PKey::RSA.new(rsa_private_key).public_key.to_der
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")

      assert received(signed).valid?(consumer_secret: der)
    end

    def test_an_hmac_signature_keyed_with_a_public_key_after_other_text_is_not_valid
      key = "A public key\n#{@public_key}"
      forged = build_header(consumer_secret: key, signature_method: "HMAC-SHA1")

      refute received(forged).valid?(consumer_secret: key)
    end

    def test_an_hmac_signature_is_valid_with_a_secret_that_begins_like_der
      signed = build_header(consumer_secret: "0a1b2c3d4e5f", signature_method: "HMAC-SHA1")

      assert received(signed).valid?(consumer_secret: "0a1b2c3d4e5f")
    end

    def test_an_rsa_signature_is_not_valid_with_a_secret_that_begins_like_der
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")

      refute received(signed).valid?(consumer_secret: "0a1b2c3d4e5f")
    end

    def test_an_rsa_signature_is_not_valid_with_another_kind_of_key
      ec_key = OpenSSL::PKey::EC.generate("prime256v1").public_to_pem
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")

      assert_same false, received(signed).valid?(consumer_secret: ec_key)
    end

    def test_naming_an_rsa_method_with_another_kind_of_key_raises
      ec_key = OpenSSL::PKey::EC.generate("prime256v1").public_to_pem
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")

      assert_raises(OpenSSL::PKey::PKeyError) do
        received(signed).valid?(consumer_secret: ec_key, signature_method: "RSA-SHA1")
      end
    end

    def test_a_shared_secret_is_not_parsed_as_a_key
      header = received(build_header)
      parsed = rsa_keys_parsed { header.valid?(consumer_secret: RFC5849::CONSUMER_SECRET) }

      assert_equal 0, parsed
    end

    def test_an_rsa_signature_with_a_shared_secret_parses_no_key
      header = received(build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1"))
      parsed = rsa_keys_parsed { header.valid?(consumer_secret: RFC5849::CONSUMER_SECRET) }

      assert_equal 0, parsed
    end

    def test_an_rsa_signature_parses_the_key_once
      header = received(build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1"))
      parsed = rsa_keys_parsed { header.valid?(consumer_secret: @public_key) }

      assert_equal 1, parsed
    end

    def test_an_hmac_signature_with_a_secret_that_begins_like_der_parses_it_once
      header = received(build_header(consumer_secret: "0a1b2c3d4e5f", signature_method: "HMAC-SHA1"))
      parsed = rsa_keys_parsed { header.valid?(consumer_secret: "0a1b2c3d4e5f") }

      assert_equal 1, parsed
    end

    def test_only_pem_or_what_begins_like_der_is_encoded_as_a_key
      header = received(build_header)
      encoded = [@public_key, "0a1b", "Key:\n-----BEGIN", "s3cret", ""].map { |key| header.send(:key_encoded?, key) }

      assert_equal [true, true, true, false, false], encoded
    end

    def test_an_rsa_key_is_an_rsa_key
      header = received(build_header)

      assert_same true, header.send(:rsa_key?, @public_key)
      assert_same false, header.send(:rsa_key?, "0a1b2c3d4e5f")
    end

    def test_naming_another_method_than_the_header_claims_is_exactly_not_valid
      header = received(build_header)

      assert_same false, header.valid?(consumer_secret: RFC5849::CONSUMER_SECRET, signature_method: "HMAC-SHA256")
    end

    private

    def rsa_keys_parsed
      before = RSAKeyParseCount.count
      yield
      RSAKeyParseCount.count - before
    end

    def received(header)
      SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, header.to_s)
    end
  end
end
