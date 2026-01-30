require "test_helper"

module SimpleOAuth
  class HeaderSignatureFormatTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_hmac_sha1_signature_contains_no_newlines
      signature = Signature.sign("HMAC-SHA1", "secret", "signature_base_string")

      refute_includes signature, "\n"
    end

    def test_hmac_sha256_signature_contains_no_newlines
      signature = Signature.sign("HMAC-SHA256", "secret", "signature_base_string")

      refute_includes signature, "\n"
    end

    def test_rsa_sha1_signature_contains_no_newlines
      signature = Signature.sign("RSA-SHA1", rsa_private_key, "signature_base_string")

      refute_includes signature, "\n"
    end

    def test_hmac_sha1_signature_is_base64_encoded
      signature = Signature.sign("HMAC-SHA1", "secret", "signature_base_string")

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_hmac_sha256_signature_is_base64_encoded
      signature = Signature.sign("HMAC-SHA256", "secret", "signature_base_string")

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_rsa_sha1_signature_is_base64_encoded
      signature = Signature.sign("RSA-SHA1", rsa_private_key, "signature_base_string")

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_plaintext_signature_returns_secret_unchanged
      signature = Signature.sign("PLAINTEXT", "secret&token_secret", "signature_base_string")

      assert_equal "secret&token_secret", signature
    end

    def test_plaintext_signature_ignores_signature_base
      sig1 = Signature.sign("PLAINTEXT", "secret&token_secret", "base1")
      sig2 = Signature.sign("PLAINTEXT", "secret&token_secret", "base2")

      assert_equal sig1, sig2
    end
  end
end
