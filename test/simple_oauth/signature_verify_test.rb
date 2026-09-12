# frozen_string_literal: true

require "test_helper"

module SimpleOAuth
  # Tests for verifying signatures through the registry
  class SignatureVerifyTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Signature*"

    BASE = "GET&https%3A%2F%2Fphotos.example.net%2Fphotos&oauth_version%3D1.0"

    def teardown
      SimpleOAuth::Signature.reset!
    end

    def test_recomputes_the_signature_for_methods_without_a_verifier
      signature = SimpleOAuth::Signature.sign("HMAC-SHA1", "secret&", BASE)

      assert SimpleOAuth::Signature.verify("HMAC-SHA1", "secret&", BASE, signature)
      refute SimpleOAuth::Signature.verify("HMAC-SHA1", "other&", BASE, signature)
    end

    def test_uses_a_registered_verifier
      verifier = ->(key, base, signature) { [key, base, signature].join(":").eql?("k:#{BASE}:s") }
      SimpleOAuth::Signature.register("HMAC-SHA512", verify: verifier) { |secret, base| "#{secret}#{base}" }

      assert SimpleOAuth::Signature.verify("HMAC-SHA512", "k", BASE, "s")
      refute SimpleOAuth::Signature.verify("HMAC-SHA512", "k", BASE, "other")
    end

    def test_unknown_signature_method
      error = assert_raises(ArgumentError) { SimpleOAuth::Signature.verify("HMAC-SHA512", "k", BASE, "s") }

      assert_includes error.message, "Unknown signature method: HMAC-SHA512"
    end

    def test_decode_base64
      assert_equal "\x01\x02\x03".b, SimpleOAuth::Signature.decode_base64("AQID")
    end
  end
end
