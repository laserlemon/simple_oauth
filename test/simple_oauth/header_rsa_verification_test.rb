# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests for verifying RSA signatures, which a verifier holds only a public key for
  class HeaderRSAVerificationTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"
    cover "SimpleOAuth::Signature*"

    def setup
      @key = OpenSSL::PKey::RSA.new(rsa_private_key)
      @signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA1")
      @received = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, @signed.to_s)
    end

    def test_valid_with_a_public_key
      assert @received.valid?(consumer_secret: @key.public_key.to_pem)
    end

    def test_valid_with_the_private_key
      assert @received.valid?(consumer_secret: rsa_private_key)
    end

    def test_invalid_signature_with_a_public_key
      tampered = SimpleOAuth::Header.new(:get, "#{RFC5849::PHOTOS_URL}?file=vacation.jpg", {}, @signed.to_s)

      refute tampered.valid?(consumer_secret: @key.public_key.to_pem)
    end

    def test_invalid_with_another_public_key
      other_key = OpenSSL::PKey::RSA.generate(2048)

      refute @received.valid?(consumer_secret: other_key.public_key.to_pem)
    end

    def test_rsa_sha256_with_a_public_key
      signed = build_header(consumer_secret: rsa_private_key, signature_method: "RSA-SHA256")
      received = SimpleOAuth::Header.new(:get, RFC5849::PHOTOS_URL, {}, signed.to_s)

      assert received.valid?(consumer_secret: @key.public_key.to_pem)
    end
  end
end
