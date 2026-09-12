# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests for the built-in RSA signature methods, registered fresh for each test
  class SignatureRSATest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Signature*"

    BASE = "GET&https%3A%2F%2Fphotos.example.net%2Fphotos&oauth_version%3D1.0"

    def setup
      Signature.reset!
      @key = OpenSSL::PKey::RSA.new(rsa_private_key)
    end

    def test_sha1_signature_verifies_with_the_public_key
      signature = Signature.sign("RSA-SHA1", rsa_private_key, BASE)

      assert Signature.verify("RSA-SHA1", @key.public_key.to_pem, BASE, signature)
    end

    def test_sha256_signature_verifies_with_the_public_key
      signature = Signature.sign("RSA-SHA256", rsa_private_key, BASE)

      assert Signature.verify("RSA-SHA256", @key.public_key.to_pem, BASE, signature)
    end

    def test_sha1_and_sha256_signatures_differ
      refute_equal Signature.sign("RSA-SHA1", rsa_private_key, BASE),
        Signature.sign("RSA-SHA256", rsa_private_key, BASE)
    end

    def test_verification_fails_for_another_signature_base
      signature = Signature.sign("RSA-SHA1", rsa_private_key, BASE)

      refute Signature.verify("RSA-SHA1", @key.public_key.to_pem, "#{BASE}%26a%3Db", signature)
    end

    def test_verification_fails_for_a_signature_of_another_digest
      signature = Signature.sign("RSA-SHA256", rsa_private_key, BASE)

      refute Signature.verify("RSA-SHA1", @key.public_key.to_pem, BASE, signature)
    end

    def test_rsa_methods_use_the_key_rather_than_escaped_secrets
      assert Signature.rsa?("RSA-SHA1")
      assert Signature.rsa?("RSA-SHA256")
    end
  end
end
