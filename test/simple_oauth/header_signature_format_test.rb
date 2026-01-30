require "test_helper"

module SimpleOAuth
  class HeaderSignatureFormatTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    def test_hmac_sha1_signature_contains_no_newlines
      signature = Signature.hmac_sha1("secret", "signature_base_string")

      refute_includes signature, "\n"
    end

    def test_hmac_sha256_signature_contains_no_newlines
      signature = Signature.hmac_sha256("secret", "signature_base_string")

      refute_includes signature, "\n"
    end

    def test_rsa_sha1_signature_contains_no_newlines
      signature = Signature.rsa_sha1(rsa_private_key, "signature_base_string")

      refute_includes signature, "\n"
    end

    def test_hmac_sha1_signature_is_base64_encoded
      signature = Signature.hmac_sha1("secret", "signature_base_string")

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_hmac_sha256_signature_is_base64_encoded
      signature = Signature.hmac_sha256("secret", "signature_base_string")

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_rsa_sha1_signature_is_base64_encoded
      signature = Signature.rsa_sha1(rsa_private_key, "signature_base_string")

      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, signature
    end

    def test_plaintext_signature_returns_secret_unchanged
      signature = Signature.plaintext("secret&token_secret")

      assert_equal "secret&token_secret", signature
    end

    def test_plaintext_signature_ignores_signature_base
      signature = Signature.plaintext("secret&token_secret", "ignored_signature_base")

      assert_equal "secret&token_secret", signature
    end
  end
end
