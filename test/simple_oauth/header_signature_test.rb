require "test_helper"

module SimpleOAuth
  # Tests for signature computation using RFC 5849 credentials.
  class HeaderSignatureTest < Minitest::Test
    include TestHelpers

    cover "SimpleOAuth::Header*"

    # #signature tests - dispatches to correct Signature method

    def test_signature_uses_hmac_sha1_for_hmac_sha1_method
      # RFC 5849 Section 3.4.2 - HMAC-SHA1 signature method
      header = build_header_with_fixed_credentials(signature_method: "HMAC-SHA1")

      assert_kind_of String, header.send(:signature)
      refute_empty header.send(:signature)
    end

    def test_signature_uses_hmac_sha256_for_hmac_sha256_method
      header = build_header_with_fixed_credentials(signature_method: "HMAC-SHA256")

      assert_kind_of String, header.send(:signature)
      refute_empty header.send(:signature)
    end

    def test_signature_uses_rsa_sha1_for_rsa_sha1_method
      # RFC 5849 Section 3.4.3 - RSA-SHA1 signature method
      header = build_header_with_fixed_credentials(
        consumer_secret: rsa_private_key,
        signature_method: "RSA-SHA1"
      )

      assert_kind_of String, header.send(:signature)
      refute_empty header.send(:signature)
    end

    def test_signature_uses_plaintext_for_plaintext_method
      # RFC 5849 Section 3.4.4 - PLAINTEXT signature method
      header = SimpleOAuth::Header.new(:get, "http://server.example.com/resource", {},
        consumer_key: RFC5849::PlaintextExample::CONSUMER_KEY,
        consumer_secret: RFC5849::PlaintextExample::CONSUMER_SECRET,
        token_secret: RFC5849::PlaintextExample::TOKEN_SECRET,
        signature_method: "PLAINTEXT", nonce: "7d8f3e4a", timestamp: "137131200")

      # PLAINTEXT signature is just the escaped secrets joined with &
      assert_equal "#{RFC5849::PlaintextExample::CONSUMER_SECRET}&#{RFC5849::PlaintextExample::TOKEN_SECRET}",
        header.send(:signature)
    end

    def test_signature_method_converts_dashes_to_underscores
      header1 = build_header_with_fixed_credentials(signature_method: "HMAC-SHA1")
      header2 = build_header_with_fixed_credentials(signature_method: "HMAC-SHA256")

      # Different signature methods produce different signatures
      refute_equal header1.send(:signature), header2.send(:signature)
    end

    def test_signature_method_dispatches_correctly_regardless_of_case
      # Both uppercase and lowercase signature methods should work
      header_upper = build_header_with_fixed_credentials(signature_method: "HMAC-SHA1")
      header_lower = build_header_with_fixed_credentials(signature_method: "hmac-sha1")

      # Both should produce valid signatures (non-empty base64 strings)
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header_upper.send(:signature)
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header_lower.send(:signature)
    end

    def test_same_inputs_produce_same_signature
      header1 = build_header_with_fixed_credentials(signature_method: "HMAC-SHA1")
      header2 = build_header_with_fixed_credentials(signature_method: "HMAC-SHA1")

      assert_equal header1.send(:signature), header2.send(:signature)
    end

    def test_different_secrets_produce_different_signatures
      header1 = build_header_with_fixed_credentials(consumer_secret: "secret1")
      header2 = build_header_with_fixed_credentials(consumer_secret: "secret2")

      refute_equal header1.send(:signature), header2.send(:signature)
    end

    def test_rsa_sha1_uses_raw_consumer_secret_not_escaped_secret
      # RSA-SHA1 needs the raw PEM key, not the escaped secret string
      header = build_header_with_fixed_credentials(
        consumer_secret: rsa_private_key,
        token_secret: "ignored",
        signature_method: "RSA-SHA1"
      )

      # If the secret was escaped (like for HMAC), this would fail because
      # the PEM key would be mangled
      assert_match %r{\A[A-Za-z0-9+/]+=*\z}, header.send(:signature)
    end
  end
end
